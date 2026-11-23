// Package server is the attestor: it gives a node the credential to join a
// cluster in exchange for proof that it is an Oxide instance the cluster's
// policy admits.
package server

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"

	"golang.org/x/time/rate"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/oxidecomputer/oxide-node-attestor/pkg/attestation"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/join"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/nonce"
)

const (
	// An attestation is about 9 KB; nothing a node sends is near this.
	maxBody = 64 << 10

	nodeUserPrefix = "system:node:"
	nodesGroup     = "system:nodes"
)

// ErrInstanceNotFound is an Instances lookup of an instance that does not
// exist, or that the attestor's credential cannot see.
var ErrInstanceNotFound = errors.New("instance not found")

// Instance is what the Oxide API says of an attested instance.
type Instance struct {
	ID        string
	ProjectID string
	Hostname  string
	Running   bool
}

// Instances looks an instance up by ID.
type Instances interface {
	Instance(ctx context.Context, id string) (*Instance, error)
}

// Node is the identity a credential is issued for.
type Node struct {
	Name       string
	InstanceID string
}

// Issuer mints the credential an admitted node joins with. csr is the
// node's PEM certificate request, already checked to be for node.
type Issuer interface {
	Issue(ctx context.Context, node Node, csr []byte) (*join.Response, error)
}

// Policy is which instances may join.
type Policy struct {
	SiloID    string
	ProjectID string
	// SledSerials, when set, are the only sleds an attestation may come from.
	SledSerials []string
}

type Server struct {
	Verifier  *attestation.Verifier
	Nonces    *nonce.Source
	Instances Instances
	Nodes     kubernetes.Interface
	Issuer    Issuer
	Policy    Policy
	// Limiter bounds requests across all callers, who are unauthenticated.
	Limiter *rate.Limiter
	Log     *slog.Logger
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc(
		"GET /healthz",
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) },
	)
	mux.HandleFunc("POST "+join.NoncePath, s.limited(s.handleNonce))
	mux.HandleFunc("POST "+join.JoinPath, s.limited(s.handleJoin))
	return mux
}

func (s *Server) limited(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Limiter != nil && !s.Limiter.Allow() {
			reply(w, http.StatusTooManyRequests, join.Error{Error: "too many requests"})
			return
		}
		next(w, r)
	}
}

func (s *Server) handleNonce(w http.ResponseWriter, _ *http.Request) {
	issued, err := s.Nonces.Issue()
	if err != nil {
		reply(w, http.StatusInternalServerError, join.Error{Error: "could not issue a nonce"})
		return
	}
	reply(w, http.StatusOK, join.NonceResponse{Nonce: issued})
}

// refusal is an error the node is told about, with the status it gets.
type refusal struct {
	status int
	reason string
}

func (r *refusal) Error() string { return r.reason }

func refuse(status int, format string, args ...any) error {
	return &refusal{status: status, reason: fmt.Sprintf(format, args...)}
}

func (s *Server) handleJoin(w http.ResponseWriter, r *http.Request) {
	var request join.Request
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody)).
		Decode(&request); err != nil {
		reply(w, http.StatusBadRequest, join.Error{Error: "malformed request"})
		return
	}
	response, evidence, err := s.admit(r.Context(), &request)
	log := s.Log.With("remote", r.RemoteAddr)
	if evidence != nil {
		log = log.With(
			"instance",
			evidence.InstanceID,
			"project",
			evidence.ProjectID,
			"sled",
			evidence.Sled.Serial,
		)
	}
	var refused *refusal
	switch {
	case errors.As(err, &refused):
		log.Warn("refused", "reason", refused.reason)
		reply(w, refused.status, join.Error{Error: refused.reason})
	case err != nil:
		log.Error("failed", "error", err)
		reply(
			w,
			http.StatusServiceUnavailable,
			join.Error{Error: "the attestor could not complete the request"},
		)
	default:
		log.Info("admitted", "node", response.NodeName)
		reply(w, http.StatusOK, response)
	}
}

func (s *Server) admit(
	ctx context.Context,
	request *join.Request,
) (*join.Response, *attestation.Evidence, error) {
	if err := s.Nonces.Check(request.Nonce); err != nil {
		return nil, nil, refuse(http.StatusForbidden, "%v", err)
	}
	block, rest := pem.Decode([]byte(request.CSR))
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return nil, nil, refuse(http.StatusBadRequest, "csr is not one PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil || csr.CheckSignature() != nil {
		return nil, nil, refuse(
			http.StatusBadRequest,
			"csr is not a validly signed certificate request",
		)
	}

	evidence, err := s.Verifier.Verify(
		request.Attestation,
		join.QualifyingData(request.Nonce, csr.Raw),
	)
	if err != nil {
		return nil, nil, refuse(http.StatusForbidden, "%v", err)
	}
	if evidence.SiloID != s.Policy.SiloID || evidence.ProjectID != s.Policy.ProjectID {
		return nil, evidence, refuse(
			http.StatusForbidden,
			"the instance is not in this cluster's silo and project",
		)
	}
	if len(s.Policy.SledSerials) > 0 &&
		!slices.Contains(s.Policy.SledSerials, evidence.Sled.Serial) {
		return nil, evidence, refuse(
			http.StatusForbidden,
			"the attestation is not from one of this cluster's sleds",
		)
	}

	// The attestation says what a sled claims; the API says the instance is
	// this rack's, and what it is called.
	instance, err := s.Instances.Instance(ctx, evidence.InstanceID)
	if errors.Is(err, ErrInstanceNotFound) {
		return nil, evidence, refuse(
			http.StatusForbidden,
			"the instance does not exist in this cluster's project",
		)
	}
	if err != nil {
		return nil, evidence, fmt.Errorf("looking up instance %s: %w", evidence.InstanceID, err)
	}
	if instance.ProjectID != s.Policy.ProjectID || !instance.Running {
		return nil, evidence, refuse(
			http.StatusForbidden,
			"the instance is not running in this cluster's project",
		)
	}

	node := Node{Name: instance.Hostname, InstanceID: instance.ID}
	if csr.Subject.CommonName != nodeUserPrefix+node.Name ||
		!slices.Equal(csr.Subject.Organization, []string{nodesGroup}) ||
		len(csr.DNSNames)+len(csr.IPAddresses)+len(csr.EmailAddresses)+len(csr.URIs) != 0 {
		return nil, evidence, refuse(
			http.StatusForbidden,
			"csr must be for %s%s in %s alone, the instance's hostname",
			nodeUserPrefix,
			node.Name,
			nodesGroup,
		)
	}
	if err := s.notJoined(ctx, node); err != nil {
		return nil, evidence, err
	}

	response, err := s.Issuer.Issue(ctx, node, []byte(request.CSR))
	if err != nil {
		return nil, evidence, fmt.Errorf("issuing a credential for node %s: %w", node.Name, err)
	}
	response.NodeName = node.Name
	return response, evidence, nil
}

// notJoined refuses a node that is already a healthy member: any workload on
// it can obtain an attestation for its instance, and must not get a second
// identity for it.
func (s *Server) notJoined(ctx context.Context, node Node) error {
	existing, err := s.Nodes.CoreV1().Nodes().Get(ctx, node.Name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("reading node %s: %w", node.Name, err)
	}
	for _, condition := range existing.Status.Conditions {
		if condition.Type == corev1.NodeReady && condition.Status == corev1.ConditionTrue {
			return refuse(http.StatusConflict, "node %s has already joined and is ready", node.Name)
		}
	}
	return nil
}

func reply(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
