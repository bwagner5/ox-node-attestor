// Package node is the instance's side of joining: it proves to the attestor
// which instance it is and comes back with the credential to join as.
package node

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
	"fmt"
	"io"
	"net/http"
	"strings"

	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"

	"github.com/oxidecomputer/oxide-node-attestor/pkg/attestation"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/join"
)

// Refused is the attestor declining to admit this node.
type Refused struct {
	Status int
	Reason string
}

func (r *Refused) Error() string {
	return fmt.Sprintf("the attestor refused (%d): %s", r.Status, r.Reason)
}

// Retryable reports whether asking again could go differently.
func (r *Refused) Retryable() bool {
	return r.Status == http.StatusTooManyRequests || r.Status >= http.StatusInternalServerError
}

type Options struct {
	// Attestor is the attestor's base URL.
	Attestor string
	HTTP     *http.Client
	// NodeName must be the instance's hostname.
	NodeName string
	// Attest defaults to the instance's attestation socket.
	Attest func(context.Context, [attestation.QualifyingDataSize]byte) ([]byte, error)
}

// Credential is what a node joins its cluster with.
type Credential struct {
	NodeName string
	// Key is the PEM private key Certificate is for, generated here.
	Key         []byte
	Certificate []byte
	Token       string
}

// Join generates the node's key and has the attestor issue a credential for
// it, against an attestation bound to that key.
func Join(ctx context.Context, o Options) (*Credential, error) {
	attest := o.Attest
	if attest == nil {
		attest = attestation.Attest
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "system:node:" + o.NodeName,
			Organization: []string{"system:nodes"},
		},
	}, key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}

	var nonce join.NonceResponse
	if err := post(ctx, o, join.NoncePath, nil, &nonce); err != nil {
		return nil, fmt.Errorf("requesting a nonce: %w", err)
	}
	bundle, err := attest(ctx, join.QualifyingData(nonce.Nonce, csr))
	if err != nil {
		return nil, err
	}
	var response join.Response
	if err := post(ctx, o, join.JoinPath, join.Request{
		Nonce:       nonce.Nonce,
		Attestation: bytes.TrimSpace(bundle),
		CSR: string(
			pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csr}),
		),
	}, &response); err != nil {
		return nil, fmt.Errorf("requesting a credential: %w", err)
	}
	if response.Certificate == "" && response.Token == "" {
		return nil, errors.New("the attestor returned no credential")
	}
	return &Credential{
		NodeName:    response.NodeName,
		Key:         pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Certificate: []byte(response.Certificate),
		Token:       response.Token,
	}, nil
}

func post(ctx context.Context, o Options, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		strings.TrimRight(o.Attestor, "/")+path,
		reader,
	)
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	client := o.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return err
	}
	if response.StatusCode != http.StatusOK {
		var refusal join.Error
		_ = json.Unmarshal(data, &refusal)
		if refusal.Error == "" {
			refusal.Error = response.Status
		}
		return &Refused{Status: response.StatusCode, Reason: refusal.Error}
	}
	return json.Unmarshal(data, out)
}

// Kubeconfig is the credential as the kubeconfig kubeadm discovers a
// cluster from and joins with.
func (c *Credential) Kubeconfig(server string, ca []byte) ([]byte, error) {
	const name = "oxide-node-attestor"
	user := &clientcmdapi.AuthInfo{Token: c.Token}
	if len(c.Certificate) > 0 {
		user = &clientcmdapi.AuthInfo{ClientCertificateData: c.Certificate, ClientKeyData: c.Key}
	}
	config := clientcmdapi.NewConfig()
	config.Clusters[name] = &clientcmdapi.Cluster{Server: server, CertificateAuthorityData: ca}
	config.AuthInfos[name] = user
	config.Contexts[name] = &clientcmdapi.Context{Cluster: name, AuthInfo: name}
	config.CurrentContext = name
	return clientcmd.Write(*config)
}
