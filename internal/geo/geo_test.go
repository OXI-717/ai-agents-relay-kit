package geo

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func sha(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func fixture(t *testing.T, geoip, geosite []byte) (registry.Pins, func()) {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/geoip.dat", func(w http.ResponseWriter, _ *http.Request) { w.Write(geoip) })
	mux.HandleFunc("/geosite.dat", func(w http.ResponseWriter, _ *http.Request) { w.Write(geosite) })
	srv := httptest.NewServer(mux)
	return registry.Pins{
		GeoipURL:      srv.URL + "/geoip.dat",
		GeoipSHA256:   sha(geoip),
		GeositeURL:    srv.URL + "/geosite.dat",
		GeositeSHA256: sha(geosite),
	}, srv.Close
}

// geositeDat encodes a minimal GeoSiteList: field 1 repeats GeoSite entries,
// each with country_code (field 1, length-delimited).
func geositeDat(codes ...string) []byte {
	var out []byte
	for _, c := range codes {
		entry := append([]byte{0x0a, byte(len(c))}, c...)
		out = append(out, 0x0a, byte(len(entry)))
		out = append(out, entry...)
	}
	return out
}

func TestCheckOK(t *testing.T) {
	pins, close := fixture(t, []byte("geoip"), geositeDat("YANDEX", "GEOIP-RU"))
	defer close()
	profiles := []registry.RoutingProfile{{DirectSites: []string{"geosite:yandex"}, ProxySites: []string{"domain:x"}}}
	if err := Check(context.Background(), pins, profiles); err != nil {
		t.Fatal(err)
	}
}

func TestCheckBadSHA256(t *testing.T) {
	pins, close := fixture(t, []byte("geoip"), []byte("geosite"))
	defer close()
	pins.GeositeSHA256 = strings.Repeat("0", 64)
	err := Check(context.Background(), pins, nil)
	if err == nil || !strings.Contains(err.Error(), "sha256") {
		t.Fatalf("want checksum error, got %v", err)
	}
}

func TestCheckMissingCategory(t *testing.T) {
	pins, close := fixture(t, []byte("geoip"), geositeDat("YANDEX"))
	defer close()
	profiles := []registry.RoutingProfile{{DirectSites: []string{"geosite:yandex", "geosite:nosuch"}}}
	err := Check(context.Background(), pins, profiles)
	if err == nil || !strings.Contains(err.Error(), "geosite:nosuch missing") {
		t.Fatalf("want missing category error, got %v", err)
	}
}

// Exact country_code match: GITHUB1S must not satisfy geosite:github, and a
// geosite:code@attr selector narrows the base code.
func TestCheckExactCountryCode(t *testing.T) {
	pins, close := fixture(t, []byte("geoip"), geositeDat("GITHUB1S"))
	defer close()
	profiles := []registry.RoutingProfile{{DirectSites: []string{"geosite:github"}}}
	err := Check(context.Background(), pins, profiles)
	if err == nil || !strings.Contains(err.Error(), "geosite:github missing") {
		t.Fatalf("substring match accepted as category: %v", err)
	}
	pins, close = fixture(t, []byte("geoip"), geositeDat("CATEGORY-GOV-RU"))
	defer close()
	profiles = []registry.RoutingProfile{{DirectSites: []string{"geosite:category-gov-ru@attr"}}}
	if err := Check(context.Background(), pins, profiles); err != nil {
		t.Fatalf("attribute selector rejected: %v", err)
	}
}

func TestCheckHTTPError(t *testing.T) {
	pins, close := fixture(t, []byte("geoip"), []byte("geosite"))
	defer close()
	pins.GeoipURL = "http://127.0.0.1:1/geoip.dat"
	if err := Check(context.Background(), pins, nil); err == nil {
		t.Fatal("want fetch error")
	}
}
