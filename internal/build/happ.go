package build

import (
	"encoding/json"
	"fmt"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

func proxyOutbound(r *registry.Registry, p Profile) obj {
	return proxyOutboundTag(r, p, "proxy")
}

func proxyOutboundTag(r *registry.Registry, p Profile, tag string) obj {
	sec := r.Secrets.Servers[p.Server.ID]
	return obj{
		"tag": tag, "protocol": "vless",
		"settings": obj{"vnext": []obj{{
			"address": p.Server.Host, "port": p.Server.Port,
			"users": []obj{{"id": p.UUID, "encryption": "none"}},
		}}},
		"streamSettings": obj{
			"network":       "xhttp",
			"xhttpSettings": obj{"path": sec.XHTTPPath, "mode": r.Transport.ClientMode, "xmux": r.Transport.Xmux},
			"security":      "reality",
			"realitySettings": obj{
				"serverName": p.Server.Reality.ServerNames[0], "fingerprint": "chrome",
				"publicKey": p.Server.Reality.PublicKey, "shortId": sec.ShortID, "spiderX": "/",
			},
			"sockopt": obj{"dialerProxy": "fragment"},
		},
	}
}

func ClientConfig(r *registry.Registry, p Profile, socksPort int, rp registry.RoutingProfile) ([]byte, error) {
	return clientConfig(r, p.Name, proxyOutbound(r, p), socksPort, rp)
}

// routingRules builds the direct/proxy split from the routing profile. proxyRoute
// is how proxied traffic leaves: {"outboundTag": "proxy"} for single-hop configs
// or {"balancerTag": ...} for failover chains.
//
// Первым правилом — DNS-IP в direct, мимо прокси/балансера (инцидент 8.10 и
// 9.10: в TUN-режиме системный DNS идёт пакетами на адреса из dns.servers,
// ловился catch-all-ом и умирал вместе с прокси-хопом → блэкаут всего
// интернета, включая RU-сайты, при живом канале до резолвера. Применяется
// ко ВСЕМ клиентским конфигам, не только к failover-цепочкам).
// Правило эмитится только при наличии литеральных IP: пустое "ip": [] в xray —
// правило без условий; не-IP резолверы отлавливает vpn validate.
// head — правила, вставляемые сразу после DNS-правила (цепочные loopback-правила
// failover-конфигов); split-правила профиля идут всегда после них.
func routingRules(r *registry.Registry, rp registry.RoutingProfile, proxyRoute obj, head ...obj) []obj {
	rules := []obj{}
	if dnsIPs := dnsServerIPs(r); len(dnsIPs) > 0 {
		rules = append(rules, obj{"type": "field", "ip": dnsIPs, "outboundTag": "direct"})
	}
	rules = append(rules, head...)
	if len(rp.DirectSites) > 0 {
		rules = append(rules, obj{"type": "field", "domain": rp.DirectSites, "outboundTag": "direct"})
	}
	if len(rp.DirectIP) > 0 {
		rules = append(rules, obj{"type": "field", "ip": rp.DirectIP, "outboundTag": "direct"})
	}
	if len(rp.ProxySites) > 0 {
		proxy := obj{"type": "field", "domain": rp.ProxySites}
		for k, v := range proxyRoute {
			proxy[k] = v
		}
		rules = append(rules, proxy)
	}
	if len(rp.ProxyIP) > 0 {
		proxy := obj{"type": "field", "ip": rp.ProxyIP}
		for k, v := range proxyRoute {
			proxy[k] = v
		}
		rules = append(rules, proxy)
	}
	catchAll := obj{"type": "field", "network": "tcp,udp"}
	for k, v := range proxyRoute {
		catchAll[k] = v
	}
	return append(rules, catchAll)
}

// clientConfig wraps a proxy outbound into a full client config with our DNS and routing.
func clientConfig(r *registry.Registry, name string, proxy obj, socksPort int, rp registry.RoutingProfile) ([]byte, error) {
	cfg := obj{
		"remarks": name,
		"log":     obj{"loglevel": "warning"},
		"dns":     obj{"servers": r.Transport.DNS, "queryStrategy": "UseIPv4"},
		"inbounds": []obj{{
			"tag": "socks", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": obj{"udp": true, "auth": "noauth"},
			"sniffing": obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		}},
		"outbounds": []obj{
			proxy,
			{"tag": "direct", "protocol": "freedom"},
			{"tag": "fragment", "protocol": "freedom", "settings": obj{"fragment": r.Transport.Fragment}},
			{"tag": "block", "protocol": "blackhole"},
		},
		"routing": obj{"domainStrategy": "IPIfNonMatch", "rules": routingRules(r, rp, obj{"outboundTag": "proxy"})},
	}
	return json.Marshal(cfg)
}

func HappSubscription(r *registry.Registry, u registry.User) ([]byte, error) {
	ps, err := Profiles(r, u)
	if err != nil {
		return nil, err
	}
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
