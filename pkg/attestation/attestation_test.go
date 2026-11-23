package attestation_test

import (
	"bytes"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/bwagner5/ox-node-attestor/pkg/attestation"
	"github.com/bwagner5/ox-node-attestor/pkg/attestation/attestationtest"
)

const (
	instance = "4d1e0c5e-0000-4000-8000-000000000001"
	project  = "92550c8a-0000-4000-8000-000000000002"
	silo     = "7bd7623a-0000-4000-8000-000000000003"
)

func TestVerify(t *testing.T) {
	rot := attestationtest.New(t, "BRM42220083")
	qd := [32]byte{1, 2, 3}
	evidence, err := (&attestation.Verifier{Roots: rot.Roots()}).Verify(
		rot.Attest(t, instance, project, silo, qd),
		qd,
	)
	if err != nil {
		t.Fatal(err)
	}
	want := attestation.Evidence{
		InstanceID: instance, ProjectID: project, SiloID: silo,
		Sled: attestation.Sled{Part: "913-0000019", Revision: "006", Serial: "BRM42220083"},
	}
	if *evidence != want {
		t.Errorf("evidence %+v, want %+v", *evidence, want)
	}
}

func TestVerifyRejects(t *testing.T) {
	rot := attestationtest.New(t, "BRM42220083")
	other := attestationtest.New(t, "BRM00000000")
	qd := [32]byte{1, 2, 3}
	good := rot.Attest(t, instance, project, silo, qd)
	verifier := &attestation.Verifier{Roots: rot.Roots()}

	for name, test := range map[string]struct {
		verifier *attestation.Verifier
		bundle   []byte
		qd       [32]byte
		want     string
	}{
		"other qualifying data": {verifier, good, [32]byte{9}, "signature does not match"},
		"another root":          {verifier, other.Attest(t, instance, project, silo, qd), qd, "certificate chain"},
		// The claims are covered by the signature.
		"an edited instance": {
			verifier,
			bytes.Replace(good, digits(t, instance), digits(t, strings.Replace(instance, "4d1e", "4d1f", 1)), 1),
			qd, "signature does not match",
		},
		"an expired chain": {
			&attestation.Verifier{Roots: rot.Roots(), Now: func() time.Time { return time.Now().Add(48 * time.Hour) }},
			good, qd, "certificate chain",
		},
		"an error response": {verifier, []byte(`{"Error":"busy"}`), qd, "busy"},
		"no trusted roots":  {&attestation.Verifier{}, good, qd, "certificate chain"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := test.verifier.Verify(test.bundle, test.qd)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Errorf("got %v, want an error containing %q", err, test.want)
			}
		})
	}
}

// digits is s as the bundle spells bytes: comma-separated numbers.
func digits(t *testing.T, s string) []byte {
	t.Helper()
	out := make([]string, 0, len(s))
	for _, b := range []byte(s) {
		out = append(out, strconv.Itoa(int(b)))
	}
	return []byte(strings.Join(out, ","))
}
