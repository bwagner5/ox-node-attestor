package attestation

import (
	"bufio"
	"net"
	"testing"
)

func TestExchange(t *testing.T) {
	client, server := net.Pipe()
	defer func() { _ = client.Close() }()
	go func() {
		defer func() { _ = server.Close() }()
		request, _ := bufio.NewReader(server).ReadString('\n')
		// What the hypervisor's server parses: 32 numbers on one line.
		want := `{"Attest":[1,2,255,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}` + "\n"
		if request != want {
			_, _ = server.Write([]byte(`{"Error":"unexpected request"}` + "\n"))
			return
		}
		_, _ = server.Write([]byte(`{"Attest":{}}` + "\n" + "trailing"))
	}()
	response, err := exchange(client, [QualifyingDataSize]byte{1, 2, 255})
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != `{"Attest":{}}`+"\n" {
		t.Errorf("response %q", response)
	}
}
