// Package issuer mints the credentials an admitted node joins with.
package issuer

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	certificatesv1 "k8s.io/api/certificates/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"

	"github.com/oxidecomputer/oxide-node-attestor/pkg/join"
	"github.com/oxidecomputer/oxide-node-attestor/pkg/server"
)

// InstanceAnnotation records, on a CertificateSigningRequest, the instance
// whose attestation it was approved for.
const InstanceAnnotation = "oxide.computer/instance-id"

// Certificate has the cluster sign a short-lived kubelet client certificate
// for the node's own key. The kubelet joins with it and renews it for a
// lasting one, which a cluster approves for any node renewing its own.
type Certificate struct {
	Client kubernetes.Interface
	// TTL is how long the certificate lasts; the API allows no less than 10m.
	TTL time.Duration
	// Timeout bounds the wait for the cluster's signer.
	Timeout time.Duration
}

func (c *Certificate) Issue(
	ctx context.Context,
	node server.Node,
	csr []byte,
) (*join.Response, error) {
	ttl := int32(c.TTL.Seconds())
	requests := c.Client.CertificatesV1().CertificateSigningRequests()
	created, err := requests.Create(ctx, &certificatesv1.CertificateSigningRequest{
		GenerateName: "oxide-node-",
		Annotations:  map[string]string{InstanceAnnotation: node.InstanceID},
		Spec: certificatesv1.CertificateSigningRequestSpec{
			Request:           csr,
			SignerName:        certificatesv1.KubeAPIServerClientKubeletSignerName,
			ExpirationSeconds: &ttl,
			Usages: []certificatesv1.KeyUsage{
				certificatesv1.UsageDigitalSignature,
				certificatesv1.UsageClientAuth,
			},
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("creating the certificate signing request: %w", err)
	}
	created.Status.Conditions = append(
		created.Status.Conditions,
		certificatesv1.CertificateSigningRequestCondition{
			Type:   certificatesv1.CertificateApproved,
			Status: corev1.ConditionTrue,
			Reason: "OxideAttestation",
			Message: fmt.Sprintf(
				"Instance %s attested to the key in this request.",
				node.InstanceID,
			),
		},
	)
	if _, err := requests.UpdateApproval(
		ctx,
		created.Name,
		created,
		metav1.UpdateOptions{},
	); err != nil {
		return nil, fmt.Errorf("approving certificate signing request %s: %w", created.Name, err)
	}

	var certificate []byte
	err = wait.PollUntilContextTimeout(
		ctx,
		200*time.Millisecond,
		c.Timeout,
		true,
		func(ctx context.Context) (bool, error) {
			current, err := requests.Get(ctx, created.Name, metav1.GetOptions{})
			if err != nil {
				return false, err
			}
			for _, condition := range current.Status.Conditions {
				if condition.Type == certificatesv1.CertificateFailed ||
					condition.Type == certificatesv1.CertificateDenied {
					return false, fmt.Errorf("%s: %s", condition.Reason, condition.Message)
				}
			}
			certificate = current.Status.Certificate
			return len(certificate) > 0, nil
		},
	)
	if err != nil {
		return nil, fmt.Errorf(
			"waiting for certificate signing request %s to be signed: %w",
			created.Name,
			err,
		)
	}
	if block, _ := pem.Decode(certificate); block == nil {
		return nil, errors.New("the signer returned no PEM certificate")
	}
	return &join.Response{Certificate: string(certificate)}, nil
}
