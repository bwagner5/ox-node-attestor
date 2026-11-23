// Package attestation verifies the attestations an Oxide instance requests
// from its sled's root of trust (RFD 605).
package attestation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// QualifyingDataSize is how many caller-chosen bytes an attestation signs.
const QualifyingDataSize = 32

const (
	platformLog = "OxidePlatform"
	instanceLog = "OxideInstance"

	// A hubpack-encoded signature: a variant byte, then Ed25519.
	signatureSize    = 1 + ed25519.SignatureSize
	signatureEd25519 = 0
)

// Go's verifier rejects a chain carrying a critical extension it does not
// know, and every certificate the root of trust derives carries this one.
var diceTCBInfo = asn1.ObjectIdentifier{2, 23, 133, 5, 4, 1}

// Evidence is what a verified attestation proves.
type Evidence struct {
	InstanceID string
	ProjectID  string
	SiloID     string
	// BootDigest is "<algorithm>:<hex>" for a read-only boot disk, else empty.
	BootDigest string
	Sled       Sled
}

// Sled identifies the hardware that signed, from its platform identity
// certificate.
type Sled struct {
	Part     string
	Revision string
	Serial   string
}

type bundle struct {
	Attest *struct {
		Attestation     []byte   `json:"attestation"`
		CertChain       [][]byte `json:"cert_chain"`
		MeasurementLogs []struct {
			RoT  string `json:"rot"`
			Data []byte `json:"data"`
		} `json:"measurement_logs"`
	} `json:"Attest"`
	Error string `json:"Error"`
}

type instanceConf struct {
	UUID       string            `json:"uuid"`
	Project    string            `json:"project"`
	Silo       string            `json:"silo"`
	BootDigest map[string]string `json:"boot-digest"`
}

// Verifier checks attestations against the platform identity roots it trusts.
type Verifier struct {
	Roots *x509.CertPool
	// Now defaults to time.Now.
	Now func() time.Time
}

// Verify checks that raw, the response of an instance's attestation socket,
// was signed over qualifyingData by a sled whose identity chains to a
// trusted root.
func (v *Verifier) Verify(raw []byte, qualifyingData [QualifyingDataSize]byte) (*Evidence, error) {
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("decoding attestation: %w", err)
	}
	if b.Attest == nil {
		if b.Error != "" {
			return nil, fmt.Errorf("attestation is an error response: %s", b.Error)
		}
		return nil, errors.New("attestation is empty")
	}
	logs := map[string][]byte{}
	for _, log := range b.Attest.MeasurementLogs {
		if _, dup := logs[log.RoT]; dup {
			return nil, fmt.Errorf("attestation has two %s measurement logs", log.RoT)
		}
		logs[log.RoT] = log.Data
	}
	if len(logs) != 2 || logs[platformLog] == nil || logs[instanceLog] == nil {
		return nil, fmt.Errorf(
			"attestation needs exactly the %s and %s measurement logs",
			platformLog,
			instanceLog,
		)
	}

	leaf, sled, err := v.verifyChain(b.Attest.CertChain)
	if err != nil {
		return nil, err
	}
	key, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("attestation key is %s, want Ed25519", leaf.PublicKeyAlgorithm)
	}
	signature := b.Attest.Attestation
	if len(signature) != signatureSize || signature[0] != signatureEd25519 {
		return nil, errors.New("attestation signature is not an Ed25519 signature")
	}

	// The instance's hypervisor folds its own log into the qualifying data
	// before the root of trust signs over the platform's.
	inner := sha256.New()
	inner.Write(logs[instanceLog])
	inner.Write(qualifyingData[:])
	outer := sha3.New256()
	outer.Write(logs[platformLog])
	outer.Write(inner.Sum(nil))
	if !ed25519.Verify(key, outer.Sum(nil), signature[1:]) {
		return nil, errors.New("attestation signature does not match")
	}

	var conf instanceConf
	if err := json.Unmarshal(logs[instanceLog], &conf); err != nil {
		return nil, fmt.Errorf("decoding the instance measurement log: %w", err)
	}
	if conf.UUID == "" || conf.Project == "" || conf.Silo == "" {
		return nil, errors.New("attestation does not name an instance, project and silo")
	}
	evidence := &Evidence{
		InstanceID: conf.UUID,
		ProjectID:  conf.Project,
		SiloID:     conf.Silo,
		Sled:       sled,
	}
	for algorithm, digest := range conf.BootDigest {
		evidence.BootDigest = algorithm + ":" + digest
	}
	return evidence, nil
}

func (v *Verifier) verifyChain(chain [][]byte) (*x509.Certificate, Sled, error) {
	if len(chain) == 0 {
		return nil, Sled{}, errors.New("attestation has no certificates")
	}
	certs := make([]*x509.Certificate, len(chain))
	for i, der := range chain {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, Sled{}, fmt.Errorf("parsing attestation certificate %d: %w", i, err)
		}
		cert.UnhandledCriticalExtensions = slices.DeleteFunc(
			cert.UnhandledCriticalExtensions,
			diceTCBInfo.Equal,
		)
		certs[i] = cert
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	now := time.Now
	if v.Now != nil {
		now = v.Now
	}
	verified, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         v.Roots,
		Intermediates: intermediates,
		CurrentTime:   now(),
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, Sled{}, fmt.Errorf("verifying the attestation certificate chain: %w", err)
	}
	// Only a certificate on the verified path identifies the signing sled;
	// the bundle may carry others.
	for _, path := range verified {
		for _, cert := range path {
			if sled, ok := parseSled(cert.Subject.CommonName); ok {
				return certs[0], sled, nil
			}
		}
	}
	return nil, Sled{}, errors.New(
		"no platform identity certificate in the attestation certificate chain",
	)
}

// parseSled reads a platform identity string, "PDV1:<part>:<revision>:<serial>".
func parseSled(commonName string) (Sled, bool) {
	fields := strings.Split(commonName, ":")
	if len(fields) != 4 || !slices.Contains([]string{"PDV1", "PDV2", "0XV1", "0XV2"}, fields[0]) {
		return Sled{}, false
	}
	return Sled{Part: fields[1], Revision: fields[2], Serial: fields[3]}, true
}
