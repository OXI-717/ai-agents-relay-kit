// Package gen creates all random secrets of the registry.
package gen

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"

	"github.com/google/uuid"
)

func randHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func Token() (string, error)   { return randHex(20) }
func ShortID() (string, error) { return randHex(4) }
func HMACKey() (string, error) { return randHex(32) }
func UUID() string             { return uuid.NewString() }

func Path() (string, error) {
	h, err := randHex(6)
	return "/" + h, err
}

func RealityKeys() (priv, pub string, err error) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return "", "", err
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(k.Bytes()), enc.EncodeToString(k.PublicKey().Bytes()), nil
}
