package server_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/time/rate"
	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/fake"
	k8stesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/oxidecomputer/oxide-node-attestor/pkg/attestation"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/attestation/attestationtest"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/issuer"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/join"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/node"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/nonce"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/server"
)

const (
	instanceID = "4d1e0c5e-0000-4000-8000-000000000001"
	projectID  = "92550c8a-0000-4000-8000-000000000002"
	siloID     = "7bd7623a-0000-4000-8000-000000000003"
	hostname   = "karpenter-default-x7k2p"
	serial     = "BRM42220083"
)

type instances map[string]*server.Instance

func (i instances) Instance(_ context.Context, id string) (*server.Instance, error) {
	if id == "broken" {
		return nil, errors.New("the API is down")
	}
	if instance, ok := i[id]; ok {
		return instance, nil
	}
	return nil, server.ErrInstanceNotFound
}

type harness struct {
	rot       *attestationtest.RoT
	cluster   *fake.Clientset
	instances instances
	attestor  *server.Server
	http      *httptest.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		rot:     attestationtest.New(t, serial),
		cluster: fake.NewClientset(),
		instances: instances{
			instanceID: {ID: instanceID, ProjectID: projectID, Hostname: hostname, Running: true},
		},
	}
	signApproved(t, h.cluster)
	h.attestor = &server.Server{
		Verifier:  &attestation.Verifier{Roots: h.rot.Roots()},
		Nonces:    nonce.New([]byte("0123456789abcdef0123456789abcdef"), time.Minute),
		Instances: h.instances,
		Nodes:     h.cluster,
		Issuer: &issuer.Certificate{
			Client:  h.cluster,
			TTL:     10 * time.Minute,
			Timeout: 5 * time.Second,
		},
		Policy: server.Policy{SiloID: siloID, ProjectID: projectID},
		Log:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	h.http = httptest.NewTLSServer(h.attestor.Handler())
	t.Cleanup(h.http.Close)
	return h
}

// signApproved stands in for kube-controller-manager's signer: an approved
// request gets a certificate for its subject and key.
func signApproved(t *testing.T, cluster *fake.Clientset) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "kubernetes"},
		IsCA:         true,
	}
	cluster.PrependReactor(
		"update",
		"certificatesigningrequests",
		func(action k8stesting.Action) (bool, runtime.Object, error) {
			if action.GetSubresource() != "approval" {
				return false, nil, nil
			}
			request := action.(k8stesting.UpdateAction).GetObject().(*certificatesv1.CertificateSigningRequest).DeepCopy()
			block, _ := pem.Decode(request.Spec.Request)
			csr, err := x509.ParseCertificateRequest(block.Bytes)
			if err != nil {
				return true, nil, err
			}
			der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
				SerialNumber: big.NewInt(2),
				Subject:      csr.Subject,
				NotAfter: time.Now().
					Add(time.Duration(*request.Spec.ExpirationSeconds) * time.Second),
			}, ca, csr.PublicKey, caKey)
			if err != nil {
				return true, nil, err
			}
			request.Status.Certificate = pem.EncodeToMemory(
				&pem.Block{Type: "CERTIFICATE", Bytes: der},
			)
			err = cluster.Tracker().Update(action.GetResource(), request, "")
			return true, request, err
		},
	)
}

// attempt is one node's try at joining; the zero value is the honest one.
type attempt struct {
	instance, project, silo string
	nodeName                string
	dnsNames                []string
	nonce                   string
	// swapCSR sends a request other than the one attested to.
	swapCSR bool
}

func (h *harness) try(t *testing.T, a attempt) (int, join.Response, string) {
	t.Helper()
	fill := func(value *string, fallback string) {
		if *value == "" {
			*value = fallback
		}
	}
	fill(&a.instance, instanceID)
	fill(&a.project, projectID)
	fill(&a.silo, siloID)
	fill(&a.nodeName, hostname)
	if a.nonce == "" {
		var err error
		if a.nonce, err = h.attestor.Nonces.Issue(); err != nil {
			t.Fatal(err)
		}
	}
	csr := newCSR(t, a.nodeName, a.dnsNames)
	bundle := h.rot.Attest(t, a.instance, a.project, a.silo, join.QualifyingData(a.nonce, csr))
	if a.swapCSR {
		csr = newCSR(t, a.nodeName, a.dnsNames)
	}
	body, err := json.Marshal(join.Request{
		Nonce:       a.nonce,
		Attestation: bytes.TrimSpace(bundle),
		CSR: string(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
		),
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := h.http.Client().
		Post(h.http.URL+join.JoinPath, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	data, _ := io.ReadAll(response.Body)
	var ok join.Response
	var refused join.Error
	_ = json.Unmarshal(data, &ok)
	_ = json.Unmarshal(data, &refused)
	return response.StatusCode, ok, refused.Error
}

func newCSR(t *testing.T, nodeName string, dnsNames []string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "system:node:" + nodeName,
			Organization: []string{"system:nodes"},
		},
		DNSNames: dnsNames,
	}, key)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func (h *harness) addNode(t *testing.T, ready corev1.ConditionStatus) {
	t.Helper()
	_, err := h.cluster.CoreV1().Nodes().Create(context.Background(), &corev1.Node{
		Name: hostname,
		Status: corev1.NodeStatus{
			Conditions: []corev1.NodeCondition{{Type: corev1.NodeReady, Status: ready}},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
}

// The whole exchange as a node runs it, ending in the kubeconfig it joins
// with.
func TestNodeJoinsWithACertificateForItsOwnKey(t *testing.T) {
	h := newHarness(t)
	credential, err := node.Join(context.Background(), node.Options{
		Attestor: h.http.URL,
		HTTP:     h.http.Client(),
		NodeName: hostname,
		Attest: func(_ context.Context, qd [32]byte) ([]byte, error) {
			return h.rot.Attest(t, instanceID, projectID, siloID, qd), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if credential.NodeName != hostname || credential.Token != "" {
		t.Errorf("credential for %q with token %q", credential.NodeName, credential.Token)
	}
	block, _ := pem.Decode(credential.Certificate)
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, _ := pem.Decode(credential.Key)
	key, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Subject.CommonName != "system:node:"+hostname ||
		!key.PublicKey.Equal(certificate.PublicKey) {
		t.Errorf(
			"certificate for %q does not match the node's name and key",
			certificate.Subject.CommonName,
		)
	}
	if left := time.Until(certificate.NotAfter); left > 10*time.Minute {
		t.Errorf("certificate lasts %s, want no more than 10m", left)
	}

	requests, err := h.cluster.CertificatesV1().
		CertificateSigningRequests().
		List(context.Background(), metav1.ListOptions{})
	if err != nil || len(requests.Items) != 1 {
		t.Fatalf("%d certificate signing requests (%v), want 1", len(requests.Items), err)
	}
	request := requests.Items[0]
	if request.Spec.SignerName != certificatesv1.KubeAPIServerClientKubeletSignerName ||
		*request.Spec.ExpirationSeconds != 600 || request.Annotations[issuer.InstanceAnnotation] != instanceID {
		t.Errorf("request %+v, annotations %v", request.Spec, request.Annotations)
	}

	kubeconfig, err := credential.Kubeconfig("https://api.example:443", []byte("ca"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := clientcmd.Load(kubeconfig)
	if err != nil {
		t.Fatal(err)
	}
	user := config.AuthInfos[config.Contexts[config.CurrentContext].AuthInfo]
	if !bytes.Equal(user.ClientCertificateData, credential.Certificate) ||
		!bytes.Equal(user.ClientKeyData, credential.Key) {
		t.Error("the kubeconfig does not carry the certificate and its key")
	}
}

func TestRefusals(t *testing.T) {
	other := "aaaaaaaa-0000-4000-8000-00000000000a"
	for name, test := range map[string]struct {
		attempt attempt
		setup   func(*testing.T, *harness)
		status  int
		reason  string
	}{
		"another project":                   {attempt{project: other}, nil, 403, "silo and project"},
		"another silo":                      {attempt{silo: other}, nil, 403, "silo and project"},
		"an instance the API does not know": {attempt{instance: other}, nil, 403, "does not exist"},
		"a stopped instance": {attempt{}, func(_ *testing.T, h *harness) {
			h.instances[instanceID].Running = false
		}, 403, "not running"},
		"an instance the API puts elsewhere": {attempt{}, func(_ *testing.T, h *harness) {
			h.instances[instanceID].ProjectID = other
		}, 403, "not running in this cluster's project"},
		"a sled off the list": {attempt{}, func(_ *testing.T, h *harness) {
			h.attestor.Policy.SledSerials = []string{"BRM00000000"}
		}, 403, "sleds"},
		"another node's name":    {attempt{nodeName: "control-plane-1"}, nil, 403, "csr must be for system:node:" + hostname},
		"a request with a SAN":   {attempt{dnsNames: []string{"kubernetes"}}, nil, 403, "csr must be for"},
		"a request not attested": {attempt{swapCSR: true}, nil, 403, "signature does not match"},
		"a nonce it made up":     {attempt{nonce: "AAAA"}, nil, 403, "not issued"},
		"a node already ready": {attempt{}, func(t *testing.T, h *harness) {
			h.addNode(t, corev1.ConditionTrue)
		}, 409, "already joined"},
		"an API outage": {attempt{instance: "broken"}, nil, 503, "could not complete"},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t)
			if test.setup != nil {
				test.setup(t, h)
			}
			status, response, reason := h.try(t, test.attempt)
			if status != test.status || !strings.Contains(reason, test.reason) {
				t.Errorf(
					"got %d %q, want %d and a reason containing %q",
					status,
					reason,
					test.status,
					test.reason,
				)
			}
			if response.Certificate != "" || response.Token != "" {
				t.Error("a refusal carried a credential")
			}
			requests, _ := h.cluster.CertificatesV1().
				CertificateSigningRequests().
				List(context.Background(), metav1.ListOptions{})
			if len(requests.Items) != 0 {
				t.Error("a refusal left a certificate signing request")
			}
		})
	}
}

func TestExpiredNonce(t *testing.T) {
	h := newHarness(t)
	h.attestor.Nonces = nonce.New([]byte("0123456789abcdef0123456789abcdef"), -time.Second)
	if status, _, reason := h.try(
		t,
		attempt{},
	); status != 403 ||
		!strings.Contains(reason, "expired") {
		t.Errorf("got %d %q", status, reason)
	}
}

// A node that stopped reporting may come back as itself.
func TestNodeNotReadyMayRejoin(t *testing.T) {
	h := newHarness(t)
	h.addNode(t, corev1.ConditionUnknown)
	if status, response, reason := h.try(
		t,
		attempt{},
	); status != 200 ||
		response.Certificate == "" {
		t.Errorf("got %d %q", status, reason)
	}
}

func TestTokenIssuer(t *testing.T) {
	h := newHarness(t)
	h.attestor.Issuer = &issuer.Token{
		Client: h.cluster,
		TTL:    2 * time.Minute,
		Groups: []string{"system:bootstrappers:kubeadm:default-node-token"},
	}
	status, response, reason := h.try(t, attempt{})
	if status != 200 || response.Certificate != "" {
		t.Fatalf("got %d %q", status, reason)
	}
	id, _, ok := strings.Cut(response.Token, ".")
	if !ok {
		t.Fatalf("token %q", response.Token)
	}
	secret, err := h.cluster.CoreV1().
		Secrets("kube-system").
		Get(context.Background(), "bootstrap-token-"+id, metav1.GetOptions{})
	if err != nil {
		t.Fatal(err)
	}
	expires, err := time.Parse(time.RFC3339, secret.StringData["expiration"])
	if err != nil || time.Until(expires) > 2*time.Minute {
		t.Errorf("token expires %v (%v), want within 2m", expires, err)
	}
	if secret.Type != corev1.SecretTypeBootstrapToken ||
		secret.Annotations[issuer.InstanceAnnotation] != instanceID {
		t.Errorf("secret type %q, annotations %v", secret.Type, secret.Annotations)
	}
}

func TestRateLimit(t *testing.T) {
	h := newHarness(t)
	h.attestor.Limiter = rate.NewLimiter(0, 1)
	post := func() int {
		response, err := h.http.Client().Post(h.http.URL+join.NoncePath, "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}
	if first, second := post(), post(); first != http.StatusOK ||
		second != http.StatusTooManyRequests {
		t.Errorf("got %d then %d", first, second)
	}
}
