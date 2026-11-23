// oxide-node-join runs on an Oxide instance before it joins a cluster: it
// attests to the cluster's attestor and writes the kubeconfig to join with.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/oxidecomputer/oxide-node-attestor/pkg/node"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/version"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "oxide-node-join:", err)
		os.Exit(1)
	}
}

func run() error {
	hostname, _ := os.Hostname()
	var (
		attestor       = flag.String("attestor", "", "URL of the cluster's attestor (required)")
		attestorCAFile = flag.String(
			"attestor-ca-file",
			"",
			"CA bundle the attestor's certificate chains to (default: --cluster-ca-file)",
		)
		clusterServer = flag.String(
			"cluster-server",
			"",
			"URL of the cluster's API server (required)",
		)
		clusterCAFile = flag.String("cluster-ca-file", "", "the cluster's CA bundle (required)")
		kubeconfig    = flag.String(
			"kubeconfig",
			"",
			"where to write the kubeconfig to join with (required)",
		)
		tokenFile = flag.String(
			"token-file",
			"",
			"where to also write the join token, when the attestor issues one",
		)
		nodeName = flag.String(
			"node-name",
			hostname,
			"the node's name, which must be the instance's hostname",
		)
		timeout     = flag.Duration("timeout", 5*time.Minute, "how long to keep trying")
		showVersion = flag.Bool("version", false, "print the version and exit")
	)
	flag.Parse()
	if *showVersion {
		fmt.Println(version.Version, version.Commit)
		return nil
	}
	if *attestor == "" || *clusterServer == "" || *clusterCAFile == "" || *kubeconfig == "" {
		flag.Usage()
		return errors.New(
			"--attestor, --cluster-server, --cluster-ca-file and --kubeconfig are required",
		)
	}
	clusterCA, err := os.ReadFile(*clusterCAFile)
	if err != nil {
		return err
	}
	attestorCA := clusterCA
	if *attestorCAFile != "" {
		if attestorCA, err = os.ReadFile(*attestorCAFile); err != nil {
			return err
		}
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(attestorCA) {
		return errors.New("no certificates in the attestor's CA bundle")
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *timeout)
	defer cancel()

	options := node.Options{
		Attestor: *attestor,
		NodeName: *nodeName,
		HTTP: &http.Client{
			Timeout: time.Minute,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
			},
		},
	}
	var credential *node.Credential
	for {
		credential, err = node.Join(ctx, options)
		if err == nil {
			break
		}
		var refused *node.Refused
		if errors.As(err, &refused) && !refused.Retryable() {
			return err
		}
		fmt.Fprintln(os.Stderr, "oxide-node-join:", err, "(retrying)")
		select {
		case <-ctx.Done():
			return err
		case <-time.After(5 * time.Second):
		}
	}

	config, err := credential.Kubeconfig(*clusterServer, clusterCA)
	if err != nil {
		return err
	}
	if err := os.WriteFile(*kubeconfig, config, 0o600); err != nil {
		return err
	}
	if *tokenFile != "" && credential.Token != "" {
		if err := os.WriteFile(*tokenFile, []byte(credential.Token+"\n"), 0o600); err != nil {
			return err
		}
	}
	fmt.Printf("node %s admitted; wrote %s\n", credential.NodeName, *kubeconfig)
	return nil
}
