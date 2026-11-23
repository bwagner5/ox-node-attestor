package attestation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
)

// exchange speaks the attestation socket's protocol, one JSON line each way,
// and returns the response as received.
func exchange(conn io.ReadWriter, qualifyingData [QualifyingDataSize]byte) ([]byte, error) {
	// encoding/json writes a []byte as base64; the socket wants numbers.
	numbers := make([]int, len(qualifyingData))
	for i, b := range qualifyingData {
		numbers[i] = int(b)
	}
	request, err := json.Marshal(map[string][]int{"Attest": numbers})
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write(append(request, '\n')); err != nil {
		return nil, fmt.Errorf("requesting an attestation: %w", err)
	}
	response, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("reading the attestation: %w", err)
	}
	return response, nil
}
