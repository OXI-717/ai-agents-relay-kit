package registry

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

// XrayAPIPort is where every server's xray exposes StatsService on loopback;
// a VPN inbound on the same port makes xray fail to start.
const XrayAPIPort = 10085

var (
	slug    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,31}$`)
	hex40   = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	formats = map[string]bool{"incy": true, "happ": true}
)

func (r *Registry) Validate() []error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	ids := map[string]bool{}
	for _, s := range r.Servers {
		if !slug.MatchString(s.ID) {
			add("invalid server slug")
		}
		if ids[s.ID] {
			add("%s: duplicate server id", s.ID)
		}
		ids[s.ID] = true
		if !s.Enabled {
			continue
		}
		if s.Kind == "relay" {
			if len(s.Exits) == 0 {
				add("%s: relay needs at least one enabled exit", s.ID)
			}
			seenExits := map[string]bool{}
			for _, id := range s.Exits {
				e, ok := r.ServerByID(id)
				if !ok || !e.Enabled || e.Kind != "exit" {
					add("%s: %s must be an enabled exit", s.ID, id)
				}
				if seenExits[id] {
					add("%s: duplicate exit %s", s.ID, id)
				}
				seenExits[id] = true
			}
		}
		if s.Kind != "exit" && s.Kind != "relay" {
			add("%s: unknown kind %q", s.ID, s.Kind)
		}
		if s.Port < 1 || s.Port > 65535 {
			add("%s: port must be 1-65535", s.ID)
		}
		if s.Port == XrayAPIPort {
			add("%s: port %d is reserved for the xray stats API", s.ID, XrayAPIPort)
		}
		if s.Reality.Target == "" || len(s.Reality.ServerNames) == 0 {
			add("%s: reality.target empty (run: vpn server probe-target)", s.ID)
		}
		if s.Reality.PublicKey == "" {
			add("%s: reality.public_key empty (run: vpn server keys)", s.ID)
		}
		sec, ok := r.Secrets.Servers[s.ID]
		if !ok || sec.PrivateKey == "" || sec.ShortID == "" || sec.XHTTPPath == "" {
			add("%s: missing server secrets", s.ID)
		}
	}

	routing := map[string]bool{}
	for _, p := range r.Routing {
		routing[p.ID] = true
	}
	tokens := map[string]string{}
	for id, sec := range r.Secrets.Users {
		if sec.Token == "" {
			continue
		}
		if prev, ok := tokens[sec.Token]; ok {
			add("duplicate subscription token in %s and %s", prev, id)
		}
		tokens[sec.Token] = id
	}
	users := map[string]bool{}
	for _, u := range r.Users {
		if !slug.MatchString(u.ID) {
			add("invalid user slug")
		}
		if users[u.ID] {
			add("%s: duplicate user id", u.ID)
		}
		users[u.ID] = true
		if u.Status != "active" && u.Status != "revoked" {
			add("%s: status must be active|revoked", u.ID)
		}
		if u.Status != "active" {
			continue
		}
		if !routing[u.Routing] {
			add("%s: unknown routing %s", u.ID, u.Routing)
		}
		for _, f := range u.Formats {
			if !formats[f] {
				add("%s: unknown format %s", u.ID, f)
			}
		}
		for _, e := range u.Entries {
			if !ids[e] {
				add("%s: unknown entry %s", u.ID, e)
			}
		}
		if !hex40.MatchString(r.Secrets.Users[u.ID].Token) {
			add("%s: token must be 40 hex", u.ID)
		}
		for _, p := range r.PairsFor(u) {
			if r.Secrets.UUIDs[p.Key] == "" {
				add("%s: no UUID (run: vpn uuids fill)", p.Key)
			}
		}
	}

	// Geo files are client-facing: pinned release assets with sha256, never `latest`.
	for _, g := range [][3]string{
		{"geoip", r.Pins.GeoipURL, r.Pins.GeoipSHA256},
		{"geosite", r.Pins.GeositeURL, r.Pins.GeositeSHA256},
	} {
		name, url, sha := g[0], g[1], g[2]
		if url == "" {
			add("pins: %s_url empty", name)
		} else if strings.Contains(url, "/latest/") {
			add("pins: %s_url must pin a release asset, not latest", name)
		}
		if !hex64.MatchString(sha) {
			add("pins: %s_sha256 must be 64 hex", name)
		}
	}

	for _, p := range r.ServicePairs() {
		if r.Secrets.UUIDs[p.Key] == "" {
			add("%s: no UUID (run: vpn uuids fill)", p.Key)
		}
	}
	for _, e := range r.External {
		if !slug.MatchString(e.ID) {
			add("invalid external slug")
		}
		for _, id := range e.ShareWith {
			if !users[id] {
				add("%s: share_with unknown user %s", e.ID, id)
			}
		}
		if r.Secrets.External[e.ID] == "" {
			add("%s: missing external link", e.ID)
		}
	}

	revoked := map[string]bool{}
	for _, id := range r.Secrets.RevokedUUIDs {
		revoked[id] = true
	}
	seen := map[string]string{}
	for k, id := range r.Secrets.UUIDs {
		if prev, ok := seen[id]; ok {
			add("duplicate UUID in %s and %s", prev, k)
		}
		seen[id] = k
		if revoked[id] {
			add("%s: revoked UUID reused", k)
		}
	}

	// DNS-резолверы транспорта: литеральный IP или DoH-URL с IP-хостом
	// (https://1.1.1.1/dns-query) — на них строится DNS→direct правило
	// клиентских конфигов. DoH с доменом не подходит (бутстрап-резолв),
	// а не-IP запись дала бы "ip": [] — правило без условий (ревью 8.10).
	for i, srv := range r.Transport.DNS {
		s := strings.TrimSpace(srv)
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Hostname()
		}
		if net.ParseIP(s) == nil {
			add("transport.dns[%d] (%q): нужен литеральный IP или https://<ip>/dns-query", i, srv)
		}
	}
	return errs
}
