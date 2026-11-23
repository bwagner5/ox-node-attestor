package issuer

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/bwagner5/ox-node-attestor/pkg/join"
	"github.com/bwagner5/ox-node-attestor/pkg/server"
)

const (
	tokenAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	tokenIDSize   = 6
	tokenKeySize  = 16
)

// Token mints a short-lived bootstrap token, for distributions whose nodes
// do not get their certificates from the cluster's signing API. Unlike a
// certificate it is not bound to the node's key or name.
type Token struct {
	Client kubernetes.Interface
	TTL    time.Duration
	// Groups the token authenticates into, beyond system:bootstrappers.
	Groups []string
}

func (t *Token) Issue(ctx context.Context, node server.Node, _ []byte) (*join.Response, error) {
	id, err := random(tokenIDSize)
	if err != nil {
		return nil, err
	}
	key, err := random(tokenKeySize)
	if err != nil {
		return nil, err
	}
	secret := &corev1.Secret{
		Name:        "bootstrap-token-" + id,
		Namespace:   metav1.NamespaceSystem,
		Annotations: map[string]string{InstanceAnnotation: node.InstanceID},
		Type:        corev1.SecretTypeBootstrapToken,
		StringData: map[string]string{
			"description":                    "oxide-node-attestor token for node " + node.Name,
			"token-id":                       id,
			"token-secret":                   key,
			"expiration":                     time.Now().Add(t.TTL).UTC().Format(time.RFC3339),
			"usage-bootstrap-authentication": "true",
			"usage-bootstrap-signing":        "true",
		},
	}
	if len(t.Groups) > 0 {
		secret.StringData["auth-extra-groups"] = strings.Join(t.Groups, ",")
	}
	if _, err := t.Client.CoreV1().
		Secrets(secret.Namespace).
		Create(ctx, secret, metav1.CreateOptions{}); err != nil {
		return nil, fmt.Errorf("creating the bootstrap token: %w", err)
	}
	return &join.Response{Token: id + "." + key}, nil
}

func random(size int) (string, error) {
	out := make([]byte, size)
	if _, err := rand.Read(out); err != nil {
		return "", err
	}
	for i, b := range out {
		out[i] = tokenAlphabet[int(b)%len(tokenAlphabet)]
	}
	return string(out), nil
}
