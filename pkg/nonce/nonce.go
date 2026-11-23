// Package nonce issues challenges the attestor can check without storing.
package nonce

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"time"
)

const (
	payloadSize = 8 + 16
	size        = payloadSize + sha256.Size
)

var (
	ErrInvalid = errors.New("nonce was not issued by this attestor")
	ErrExpired = errors.New("nonce has expired")
)

// Source issues nonces that carry their own expiry, authenticated by a key.
// Replicas sharing the key accept each other's.
type Source struct {
	key []byte
	ttl time.Duration
	now func() time.Time
}

func New(key []byte, ttl time.Duration) *Source {
	return &Source{key: key, ttl: ttl, now: time.Now}
}

func (s *Source) Issue() (string, error) {
	out := make([]byte, payloadSize, size)
	binary.BigEndian.PutUint64(out, uint64(s.now().Add(s.ttl).Unix()))
	if _, err := rand.Read(out[8:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(s.mac(out)), nil
}

func (s *Source) Check(nonce string) error {
	raw, err := base64.RawURLEncoding.DecodeString(nonce)
	if err != nil || len(raw) != size {
		return ErrInvalid
	}
	if !hmac.Equal(raw, s.mac(raw[:payloadSize:payloadSize])) {
		return ErrInvalid
	}
	if s.now().Unix() > int64(binary.BigEndian.Uint64(raw)) {
		return ErrExpired
	}
	return nil
}

func (s *Source) mac(payload []byte) []byte {
	h := hmac.New(sha256.New, s.key)
	h.Write(payload)
	return h.Sum(payload)
}
