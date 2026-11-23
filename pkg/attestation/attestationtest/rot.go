// Package attestationtest stands in for a sled's root of trust in tests.
package attestationtest

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"math/big"
	"testing"
	"time"
)

// RoT signs attestations the way a sled does, under a root of its own.
type RoT struct {
	root  *x509.Certificate
	chain [][]byte
	alias ed25519.PrivateKey
	// PlatformLog is what the next attestation carries for the platform.
	PlatformLog []byte
}

// New builds a root of trust for the sled with the given serial.
func New(t *testing.T, serial string) *RoT {
	t.Helper()
	r := &RoT{PlatformLog: []byte("platform measurements")}
	var parent *x509.Certificate
	var parentKey ed25519.PrivateKey
	names := []string{
		"Platform Identity Test Root",
		"Platform Identity Test Intermediate",
		"PDV1:913-0000019:006:" + serial,
		"device-id",
		"alias",
	}
	for i, name := range names {
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		leaf := i == len(names)-1
		template := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 1)),
			Subject: pkix.Name{
				Organization: []string{"Oxide Computer Company"},
				CommonName:   name,
			},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(24 * time.Hour),
			IsCA:                  !leaf,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageDigitalSignature,
		}
		if !leaf {
			template.KeyUsage = x509.KeyUsageCertSign
		}
		if i >= 3 {
			// As on real hardware, critical and unknown to crypto/x509.
			template.ExtraExtensions = []pkix.Extension{
				{
					Id: asn1.ObjectIdentifier{
						2,
						23,
						133,
						5,
						4,
						1,
					},
					Critical: true,
					Value:    []byte{0x30, 0x00},
				},
			}
		}
		signer, signerKey := template, private
		if parent != nil {
			signer, signerKey = parent, parentKey
		}
		der, err := x509.CreateCertificate(rand.Reader, template, signer, public, signerKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		if parent == nil {
			r.root = cert
		} else {
			r.chain = append([][]byte{der}, r.chain...)
		}
		parent, parentKey = cert, private
	}
	r.alias = parentKey
	return r
}

// Roots trusts this root of trust alone.
func (r *RoT) Roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(r.root)
	return pool
}

// Attest returns the attestation socket's response for an instance.
func (r *RoT) Attest(t *testing.T, instance, project, silo string, qualifyingData [32]byte) []byte {
	t.Helper()
	conf, err := json.Marshal(
		map[string]any{"uuid": instance, "project": project, "silo": silo, "boot-digest": nil},
	)
	if err != nil {
		t.Fatal(err)
	}
	inner := sha256.New()
	inner.Write(conf)
	inner.Write(qualifyingData[:])
	outer := sha3.New256()
	outer.Write(r.PlatformLog)
	outer.Write(inner.Sum(nil))
	signature := append([]byte{0}, ed25519.Sign(r.alias, outer.Sum(nil))...)

	type log struct {
		RoT  string `json:"rot"`
		Data []int  `json:"data"`
	}
	chain := make([][]int, len(r.chain))
	for i, der := range r.chain {
		chain[i] = ints(der)
	}
	out, err := json.Marshal(map[string]any{"Attest": map[string]any{
		"attestation": ints(signature),
		"cert_chain":  chain,
		"measurement_logs": []log{
			{RoT: "OxidePlatform", Data: ints(r.PlatformLog)},
			{RoT: "OxideInstance", Data: ints(conf)},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return append(out, '\n')
}

func ints(data []byte) []int {
	out := make([]int, len(data))
	for i, b := range data {
		out[i] = int(b)
	}
	return out
}
