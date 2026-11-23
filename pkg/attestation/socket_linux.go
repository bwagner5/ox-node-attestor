package attestation

import (
	"context"
	"fmt"

	"github.com/mdlayher/vsock"
)

// The hypervisor's attestation server, as the instance reaches it.
const socketPort = 605

// Attest asks the sled's root of trust, through the instance's hypervisor,
// to sign qualifyingData, and returns its response as received.
func Attest(ctx context.Context, qualifyingData [QualifyingDataSize]byte) ([]byte, error) {
	conn, err := vsock.Dial(vsock.Host, socketPort, nil)
	if err != nil {
		return nil, fmt.Errorf("connecting to the attestation socket: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
	}
	return exchange(conn, qualifyingData)
}
