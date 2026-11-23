package node

import (
	"testing"

	"k8s.io/client-go/tools/clientcmd"
)

func TestKubeconfigCarriesAToken(t *testing.T) {
	credential := &Credential{
		NodeName: "node-1",
		Key:      []byte("unused"),
		Token:    "abcdef.0123456789abcdef",
	}
	out, err := credential.Kubeconfig("https://api.example:6443", []byte("ca"))
	if err != nil {
		t.Fatal(err)
	}
	config, err := clientcmd.Load(out)
	if err != nil {
		t.Fatal(err)
	}
	context := config.Contexts[config.CurrentContext]
	user, cluster := config.AuthInfos[context.AuthInfo], config.Clusters[context.Cluster]
	if user.Token != credential.Token || len(user.ClientKeyData) != 0 {
		t.Errorf("user %+v", user)
	}
	if cluster.Server != "https://api.example:6443" ||
		string(cluster.CertificateAuthorityData) != "ca" {
		t.Errorf("cluster %+v", cluster)
	}
}
