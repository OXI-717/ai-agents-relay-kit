package build

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func routingProfile(r *registry.Registry, id string) (registry.RoutingProfile, error) {
	for _, p := range r.Routing {
		if p.ID == id {
			return p, nil
		}
	}
	return registry.RoutingProfile{}, fmt.Errorf("unknown routing %s", id)
}

// incyRouting follows docs.incy.cc/en/routing (same shape as Happ routing profiles).
// Geo files come from pins.yaml: a pinned release asset + sha256, never `latest`.
func incyRouting(p registry.RoutingProfile, pins registry.Pins, updated int64) ([]byte, error) {
	return json.Marshal(obj{
		"Name":              p.Name,
		"GlobalProxy":       "true",
		// DoH строго по IP: инцидент 9.10 — INCY перезаписывает dns-секцию
		// конфига значениями профиля, а доменные DoH (cloudflare-dns.com,
		// dns.google) на DPI-сетях умирают: резолв по отравленному DNS
		// провайдера + QUIC udp/443 режется. IP-URL бутстрапа не требуют.
		"RemoteDNSType":     "DoH",
		"RemoteDNSDomain":   "https://1.1.1.1/dns-query",
		"RemoteDNSIP":       "1.1.1.1",
		"DomesticDNSType":   "DoH",
		"DomesticDNSDomain": "https://8.8.8.8/dns-query",
		"DomesticDNSIP":     "8.8.8.8",
		"Geoipurl":          pins.GeoipURL,
		"Geositeurl":        pins.GeositeURL,
		"DnsHosts":          obj{"cloudflare-dns.com": "1.1.1.1", "dns.google": "8.8.8.8"},
		"DirectSites":       p.DirectSites,
		"DirectIp":          p.DirectIP,
		"ProxySites":        p.ProxySites,
		"ProxyIp":           p.ProxyIP,
		"BlockSites":        []string{},
		"BlockIp":           []string{},
		"DomainStrategy":    "IPIfNonMatch",
		"FakeDNS":           "false",
		"LastUpdated":       fmt.Sprint(updated),
	})
}

// IncySubscription returns a JSON array of full xray configs
// (docs.incy.cc/en/full-xray-config): failover chains first, then one config
// per pair, then externals. A JSON body cannot carry the incy://routing line,
// so the routing profile ships via the `routing` response header (see
// IncyRoutingLink and the worker) — headers take precedence in INCY anyway.
func IncySubscription(r *registry.Registry, u registry.User, updated int64) ([]byte, error) {
	rp, err := routingProfile(r, u.Routing)
	if err != nil {
		return nil, err
	}
	var arr []json.RawMessage
	groups, err := FailoverGroups(r, u)
	if err != nil {
		return nil, err
	}
	for _, g := range groups {
		b, err := FailoverConfig(r, g, 10808, rp)
		if err != nil {
			return nil, err
		}
		arr = append(arr, b)
	}
	ps, err := Profiles(r, u)
	if err != nil {
		return nil, err
	}
	for _, p := range ps {
		b, err := ClientConfig(r, p, 10808, rp)
		if err != nil {
			return nil, err
		}
		arr = append(arr, b)
	}
	for _, e := range r.ExternalFor(u) {
		out, _, err := LinkOutbound(r.Secrets.External[e.ID])
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.ID, err)
		}
		b, err := clientConfig(r, e.Label, out, 10808, rp)
		if err != nil {
			return nil, err
		}
		arr = append(arr, b)
	}
	return json.MarshalIndent(arr, "", "  ")
}

// IncyRoutingLink activates the routing profile when the subscription body is a
// JSON array (delivered by the worker as the `routing` response header).
func IncyRoutingLink(r *registry.Registry, u registry.User, updated int64) (string, error) {
	rp, err := routingProfile(r, u.Routing)
	if err != nil {
		return "", err
	}
	rj, err := incyRouting(rp, r.Pins, updated)
	if err != nil {
		return "", err
	}
	return "incy://routing/onadd/" + base64.StdEncoding.EncodeToString(rj), nil
}

// HappRoutingLink is the routing profile Happ activates from the `routing` response header.
// Happ takes geo files from the active profile, so without it JSON subscriptions inherit
// whatever profile another subscription installed.
func HappRoutingLink(r *registry.Registry, u registry.User, updated int64) (string, error) {
	rp, err := routingProfile(r, u.Routing)
	if err != nil {
		return "", err
	}
	rj, err := incyRouting(rp, r.Pins, updated)
	if err != nil {
		return "", err
	}
	return "happ://routing/onadd/" + base64.StdEncoding.EncodeToString(rj), nil
}
