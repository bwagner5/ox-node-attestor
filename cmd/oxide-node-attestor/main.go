// oxide-node-attestor admits Oxide instances to a Kubernetes cluster: an
// instance that proves it runs in the cluster's project gets the credential
// to join as a node.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"golang.org/x/time/rate"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/bwagner5/ox-node-attestor/pkg/attestation"
	"github.com/bwagner5/ox-node-attestor/pkg/issuer"
	"github.com/bwagner5/ox-node-attestor/pkg/nonce"
	"github.com/bwagner5/ox-node-attestor/pkg/oxide"
	"github.com/bwagner5/ox-node-attestor/pkg/server"
	"github.com/bwagner5/ox-node-attestor/pkg/version"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	if err := run(log); err != nil {
		log.Error("exiting", "error", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger) error {
	var (
		listen   = flag.String("listen-address", ":8443", "address to serve on")
		certFile = flag.String(
			"tls-cert-file",
			"",
			"serving certificate, which nodes must be able to verify (required)",
		)
		keyFile   = flag.String("tls-key-file", "", "serving key (required)")
		rootsFile = flag.String(
			"platform-roots-file",
			"",
			"PEM platform identity roots attestations must chain to (required)",
		)
		project = flag.String(
			"oxide-project",
			os.Getenv("OXIDE_PROJECT"),
			"name or ID of the project whose instances may join",
		)
		sledSerials = flag.String(
			"sled-serials",
			"",
			"comma-separated serials of the only sleds attestations may come from (default: any)",
		)
		kind = flag.String(
			"issuer",
			"certificate",
			"credential to issue: certificate or token",
		)
		certificateTTL = flag.Duration(
			"certificate-ttl",
			10*time.Minute,
			"lifetime of an issued certificate; the cluster allows no less than 10m",
		)
		tokenTTL    = flag.Duration("token-ttl", 2*time.Minute, "lifetime of an issued token")
		tokenGroups = flag.String(
			"token-groups",
			"",
			"comma-separated extra groups for an issued token",
		)
		kubeconfig = flag.String(
			"kubeconfig",
			"",
			"kubeconfig for the cluster (default: in-cluster)",
		)
		nonceKeyFile = flag.String(
			"nonce-key-file",
			"",
			"key replicas share to accept each other's nonces (default: random)",
		)
		nonceTTL = flag.Duration("nonce-ttl", time.Minute, "how long a nonce is good for")
		limit    = flag.Float64(
			"rate-limit",
			20,
			"requests per second served, across all callers",
		)
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version, version.Commit)
		return nil
	}
	if *certFile == "" || *keyFile == "" || *rootsFile == "" || *project == "" {
		flag.Usage()
		return errors.New(
			"--tls-cert-file, --tls-key-file, --platform-roots-file and --oxide-project are required",
		)
	}

	rootsPEM, err := os.ReadFile(*rootsFile)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootsPEM) {
		return fmt.Errorf("no certificates in %s", *rootsFile)
	}

	key := make([]byte, 32)
	if *nonceKeyFile != "" {
		if key, err = os.ReadFile(*nonceKeyFile); err != nil {
			return err
		}
		if len(key) < 32 {
			return fmt.Errorf("%s holds fewer than 32 bytes", *nonceKeyFile)
		}
	} else if _, err := rand.Read(key); err != nil {
		return err
	}

	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return fmt.Errorf("loading the cluster's kubeconfig: %w", err)
	}
	cluster, err := kubernetes.NewForConfig(config)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	api, err := oxide.New()
	if err != nil {
		return fmt.Errorf("building the Oxide client: %w", err)
	}
	policy, err := api.Policy(ctx, *project)
	if err != nil {
		return err
	}
	policy.SledSerials = split(*sledSerials)

	var credentials server.Issuer
	switch *kind {
	case "certificate":
		credentials = &issuer.Certificate{
			Client:  cluster,
			TTL:     *certificateTTL,
			Timeout: 30 * time.Second,
		}
	case "token":
		credentials = &issuer.Token{Client: cluster, TTL: *tokenTTL, Groups: split(*tokenGroups)}
	default:
		return fmt.Errorf("unknown --issuer %q (want certificate or token)", *kind)
	}

	attestor := &server.Server{
		Verifier:  &attestation.Verifier{Roots: roots},
		Nonces:    nonce.New(key, *nonceTTL),
		Instances: api,
		Nodes:     cluster,
		Issuer:    credentials,
		Policy:    policy,
		Limiter:   rate.NewLimiter(rate.Limit(*limit), int(*limit)*2),
		Log:       log,
	}
	httpServer := &http.Server{
		Addr:              *listen,
		Handler:           attestor.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      time.Minute,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			// Read per handshake, so a rotated certificate is picked up.
			GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
				certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
				return &certificate, err
			},
		},
	}
	log.Info("serving", "version", version.Version, "address", *listen, "issuer", *kind,
		"silo", policy.SiloID, "project", policy.ProjectID, "sleds", len(policy.SledSerials))

	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdown)
	}()
	if err := httpServer.ListenAndServeTLS("", ""); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func split(list string) []string {
	var out []string
	for item := range strings.SplitSeq(list, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}
