// Package join is the protocol between a node and the attestor.
package join

import (
	"crypto/sha256"
	"encoding/json"
)

const (
	NoncePath = "/v1/nonce"
	JoinPath  = "/v1/join"
)

// NonceResponse is the reply to a POST of NoncePath.
type NonceResponse struct {
	Nonce string `json:"nonce"`
}

// Request is POSTed to JoinPath.
type Request struct {
	Nonce string `json:"nonce"`
	// Attestation is the instance's attestation socket response, signed over
	// QualifyingData(Nonce, the DER of CSR).
	Attestation json.RawMessage `json:"attestation"`
	// CSR is a PEM certificate request for the node's kubelet client
	// certificate.
	CSR string `json:"csr"`
}

// Response carries the credential the node joins with: one of Certificate,
// for the key behind the request's CSR, and Token.
type Response struct {
	NodeName    string `json:"nodeName"`
	Certificate string `json:"certificate,omitempty"`
	Token       string `json:"token,omitempty"`
}

// Error is the body of any reply that is not a 200.
type Error struct {
	Error string `json:"error"`
}

// QualifyingData binds an attestation to one nonce and one certificate
// request, so it is good for nothing else.
func QualifyingData(nonce string, csrDER []byte) [sha256.Size]byte {
	h := sha256.New()
	h.Write([]byte("oxide-node-attestor/v1\x00"))
	h.Write([]byte(nonce))
	h.Write([]byte{0})
	h.Write(csrDER)
	return [sha256.Size]byte(h.Sum(nil))
}
