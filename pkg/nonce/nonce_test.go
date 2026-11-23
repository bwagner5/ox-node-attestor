package nonce

import (
	"errors"
	"testing"
	"time"
)

func TestNonce(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	source := &Source{key: []byte("key"), ttl: time.Minute, now: func() time.Time { return now }}
	nonce, err := source.Issue()
	if err != nil {
		t.Fatal(err)
	}
	if err := source.Check(nonce); err != nil {
		t.Errorf("fresh nonce: %v", err)
	}
	if second, _ := source.Issue(); second == nonce {
		t.Error("two nonces are equal")
	}
	if err := New([]byte("another key"), time.Minute).Check(nonce); !errors.Is(err, ErrInvalid) {
		t.Errorf("nonce under another key: %v", err)
	}
	flipped := []byte(nonce)
	flipped[0] ^= 1
	for _, bad := range []string{"", "not base64!", nonce[:len(nonce)-2], string(flipped)} {
		if err := source.Check(bad); !errors.Is(err, ErrInvalid) {
			t.Errorf("%q: %v", bad, err)
		}
	}
	now = now.Add(time.Minute + time.Second)
	if err := source.Check(nonce); !errors.Is(err, ErrExpired) {
		t.Errorf("old nonce: %v", err)
	}
}
