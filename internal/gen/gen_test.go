package gen

import (
	"crypto/ecdh"
	"encoding/base64"
	"regexp"
	"testing"
)

func TestFormats(t *testing.T) {
	tok, _ := Token()
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(tok) {
		t.Fatalf("token %q", tok)
	}
	if !regexp.MustCompile(`^[0-9a-f-]{36}$`).MatchString(UUID()) {
		t.Fatal("uuid")
	}
	sid, _ := ShortID()
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(sid) {
		t.Fatalf("sid %q", sid)
	}
	p, _ := Path()
	if !regexp.MustCompile(`^/[0-9a-f]{12}$`).MatchString(p) {
		t.Fatalf("path %q", p)
	}
}

func TestRealityKeysPair(t *testing.T) {
	priv, pub, err := RealityKeys()
	if err != nil {
		t.Fatal(err)
	}
	pb, err := base64.RawURLEncoding.DecodeString(priv)
	if err != nil || len(pb) != 32 {
		t.Fatalf("priv decode: %v len %d", err, len(pb))
	}
	k, err := ecdh.X25519().NewPrivateKey(pb)
	if err != nil {
		t.Fatal(err)
	}
	if base64.RawURLEncoding.EncodeToString(k.PublicKey().Bytes()) != pub {
		t.Fatal("pub does not match priv")
	}
}

func TestTokensUnique(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok, _ := Token()
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
}
