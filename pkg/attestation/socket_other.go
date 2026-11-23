//go:build !linux

package attestation

import (
	"context"
	"errors"
)

// Attest needs the attestation socket of an Oxide instance.
func Attest(context.Context, [QualifyingDataSize]byte) ([]byte, error) {
	return nil, errors.New("attestation is only available on a Linux Oxide instance")
}
