// Package build renders server configs and client subscriptions from the registry.
package build

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

type obj = map[string]any

var privateNets = []string{
	"0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
	"172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "fc00::/7", "fe80::/10", "::1/128",
}

func ServerConfig(r *registry.Registry, s registry.Server) ([]byte, error) {
	sec, ok := r.Secrets.Servers[s.ID]
	if !ok {
		return nil, fmt.Errorf("%s: missing server secrets", s.ID)
	}
	var clients []obj
	routes := map[string][]string{}
	addClient := func(key, tag string) error {
		id := r.Secrets.UUIDs[key]
		if id == "" {
			return fmt.Errorf("%s: no UUID (run: vpn uuids fill)", key)
		}
		clients = append(clients, obj{"id": id, "email": key, "level": 0})
		routes[tag] = append(routes[tag], key)
		return nil
	}
	for _, u := range r.ActiveUsers() {
		for _, p := range r.PairsFor(u) {
			if p.Entry.ID != s.ID {
				continue
			}
			tag := "direct"
			if s.Kind == "relay" {
				tag = "via-" + p.Exit.ID
			}
			if err := addClient(p.Key, tag); err != nil {
				return nil, err
			}
		}
	}
	outbounds := []obj{{"tag": "block", "protocol": "blackhole"}}
	if s.Kind == "exit" {
		outbounds = append(outbounds, obj{"tag": "direct", "protocol": "freedom", "settings": obj{"domainStrategy": "UseIPv4"}})
		for _, p := range r.ServicePairs() {
			if p.Exit.ID == s.ID {
				if err := addClient(p.Key, "direct"); err != nil {
					return nil, err
				}
			}
		}
	} else if s.Kind == "relay" {
		for _, id := range s.Exits {
			e, ok := r.ServerByID(id)
			if !ok || !e.Enabled || e.Kind != "exit" {
				return nil, fmt.Errorf("%s: %s must be an enabled exit", s.ID, id)
			}
			key := registry.ServiceKey(s.ID, id)
			uuid := r.Secrets.UUIDs[key]
			if uuid == "" {
				return nil, fmt.Errorf("%s: no UUID (run: vpn uuids fill)", key)
			}
			if len(e.Reality.ServerNames) == 0 {
				return nil, fmt.Errorf("%s: no server names", id)
			}
			outbound := proxyOutbound(r, Profile{Server: e, UUID: uuid})
			outbound["tag"] = "via-" + id
			delete(outbound["streamSettings"].(obj), "sockopt")
			outbounds = append(outbounds, outbound)
		}
	} else {
		return nil, fmt.Errorf("%s: unknown kind", s.ID)
	}
	rules := []obj{
		{"type": "field", "protocol": []string{"bittorrent"}, "outboundTag": "block"},
		{"type": "field", "ip": privateNets, "outboundTag": "block"},
	}
	tags := make([]string, 0, len(routes))
	for tag := range routes {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	for _, tag := range tags {
		sort.Strings(routes[tag])
		rules = append(rules, obj{"type": "field", "user": routes[tag], "outboundTag": tag})
	}
	rules = append(rules, obj{"type": "field", "network": "tcp,udp", "outboundTag": "block"})
	sort.Slice(clients, func(i, j int) bool { return clients[i]["email"].(string) < clients[j]["email"].(string) })
	if clients == nil {
		clients = []obj{}
	}
	cfg := obj{
		"log":   obj{"loglevel": "error", "access": "none"},
		"stats": obj{},
		"api":   obj{"tag": "api", "listen": fmt.Sprintf("127.0.0.1:%d", registry.XrayAPIPort), "services": []string{"StatsService"}},
		"policy": obj{
			"levels": obj{"0": obj{"statsUserUplink": true, "statsUserDownlink": true}},
		},
		"inbounds": []obj{{
			"tag": "in-443", "listen": "0.0.0.0", "port": s.Port, "protocol": "vless",
			"settings": obj{"clients": clients, "decryption": "none"},
			"streamSettings": obj{
				"network":       "xhttp",
				"xhttpSettings": obj{"path": sec.XHTTPPath, "mode": r.Transport.ServerMode},
				"security":      "reality",
				"realitySettings": obj{
					"show": false, "target": s.Reality.Target, "xver": 0,
					"serverNames": s.Reality.ServerNames, "privateKey": sec.PrivateKey,
					"shortIds": []string{sec.ShortID},
				},
			},
			"sniffing": obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		}},
		"outbounds": outbounds,
		"routing":   obj{"rules": rules},
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}
