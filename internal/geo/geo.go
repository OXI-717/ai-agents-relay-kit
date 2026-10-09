// Package geo verifies the pinned geo files the routing profiles point clients at:
// the bytes behind the pinned URL must match the pinned sha256, and every
// geosite: category used by the registry must exist in the pinned geosite.dat.
package geo

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

const maxGeoSize = 64 << 20

var client = &http.Client{Timeout: 60 * time.Second}

func fetch(ctx context.Context, url, wantSHA256 string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: http %d", url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxGeoSize+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxGeoSize {
		return nil, fmt.Errorf("%s: exceeds %d bytes", url, maxGeoSize)
	}
	sum := sha256.Sum256(body)
	if got := hex.EncodeToString(sum[:]); got != wantSHA256 {
		return nil, fmt.Errorf("%s: sha256 %s, want %s", url, got, wantSHA256)
	}
	return body, nil
}

// GeositeCategories lists every geosite: category the routing profiles rely on.
func GeositeCategories(profiles []registry.RoutingProfile) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range profiles {
		for _, lst := range [][]string{p.DirectSites, p.ProxySites} {
			for _, d := range lst {
				if cat, ok := strings.CutPrefix(d, "geosite:"); ok && !seen[cat] {
					seen[cat] = true
					out = append(out, cat)
				}
			}
		}
	}
	return out
}

// geositeCodes extracts the country_code (GeoSiteList field 1 → GeoSite field 1)
// of every entry in a protobuf-encoded geosite.dat. Only the fields needed are
// decoded; everything else is skipped by wire type.
func geositeCodes(data []byte) (map[string]bool, error) {
	codes := map[string]bool{}
	for len(data) > 0 {
		tag, n := binary.Uvarint(data)
		if n <= 0 || tag>>3 == 0 {
			return nil, fmt.Errorf("geosite.dat: bad field tag")
		}
		field, wire := tag>>3, tag&7
		data = data[n:]
		if field == 1 && wire == 2 {
			entry, rest, err := consumeLen(data)
			if err != nil {
				return nil, err
			}
			data = rest
			code, err := geoSiteCode(entry)
			if err != nil {
				return nil, err
			}
			codes[strings.ToUpper(code)] = true
			continue
		}
		rest, err := skipField(data, wire)
		if err != nil {
			return nil, err
		}
		data = rest
	}
	return codes, nil
}

// geoSiteCode returns the country_code (field 1) of one GeoSite entry.
func geoSiteCode(entry []byte) (string, error) {
	for len(entry) > 0 {
		tag, n := binary.Uvarint(entry)
		if n <= 0 || tag>>3 == 0 {
			return "", fmt.Errorf("geosite.dat: bad GeoSite tag")
		}
		field, wire := tag>>3, tag&7
		entry = entry[n:]
		if field == 1 && wire == 2 {
			b, _, err := consumeLen(entry)
			return string(b), err
		}
		rest, err := skipField(entry, wire)
		if err != nil {
			return "", err
		}
		entry = rest
	}
	return "", nil
}

func consumeLen(b []byte) (field, rest []byte, err error) {
	l, n := binary.Uvarint(b)
	if n <= 0 || uint64(len(b[n:])) < l {
		return nil, nil, fmt.Errorf("geosite.dat: truncated length-delimited field")
	}
	return b[n : n+int(l)], b[n+int(l):], nil
}

func skipField(b []byte, wire uint64) ([]byte, error) {
	switch wire {
	case 0:
		_, n := binary.Uvarint(b)
		if n <= 0 {
			return nil, fmt.Errorf("geosite.dat: bad varint")
		}
		return b[n:], nil
	case 1:
		if len(b) < 8 {
			return nil, fmt.Errorf("geosite.dat: truncated 64-bit field")
		}
		return b[8:], nil
	case 2:
		_, rest, err := consumeLen(b)
		return rest, err
	case 5:
		if len(b) < 4 {
			return nil, fmt.Errorf("geosite.dat: truncated 32-bit field")
		}
		return b[4:], nil
	}
	return nil, fmt.Errorf("geosite.dat: unsupported wire type %d", wire)
}

// Check downloads both pinned geo files, verifies their sha256 and confirms that
// every used geosite: category exists in the pinned geosite.dat (group codes are
// stored uppercase in the dat file).
func Check(ctx context.Context, pins registry.Pins, profiles []registry.RoutingProfile) error {
	if _, err := fetch(ctx, pins.GeoipURL, pins.GeoipSHA256); err != nil {
		return err
	}
	geosite, err := fetch(ctx, pins.GeositeURL, pins.GeositeSHA256)
	if err != nil {
		return err
	}
	codes, err := geositeCodes(geosite)
	if err != nil {
		return err
	}
	for _, cat := range GeositeCategories(profiles) {
		// geosite:code@attr narrows the group; the check covers the base code.
		code, _, _ := strings.Cut(cat, "@")
		if !codes[strings.ToUpper(code)] {
			return fmt.Errorf("geosite:%s missing in pinned geosite.dat", cat)
		}
	}
	return nil
}
