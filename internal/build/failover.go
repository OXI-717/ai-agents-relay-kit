package build

import (
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

// FailoverGroups groups a user's pairs by exit. Each group is an ordered path
// list for one exit: relay entries first (servers.yaml order), the direct exit
// last. Only exits with two or more paths produce a group.
func FailoverGroups(r *registry.Registry, u registry.User) ([][]Profile, error) {
	ps, err := Profiles(r, u)
	if err != nil {
		return nil, err
	}
	var order []string
	seen := map[string]bool{}
	relays := map[string][]Profile{}
	direct := map[string]Profile{}
	for _, p := range ps {
		eid := p.Exit.ID
		if !seen[eid] {
			seen[eid] = true
			order = append(order, eid)
		}
		if p.Server.Kind == "relay" {
			relays[eid] = append(relays[eid], p)
		} else {
			direct[eid] = p
		}
	}
	var groups [][]Profile
	for _, eid := range order {
		g := append([]Profile{}, relays[eid]...)
		if d, ok := direct[eid]; ok {
			g = append(g, d)
		}
		if len(g) >= 2 {
			groups = append(groups, g)
		}
	}
	return groups, nil
}

func failoverName(paths []Profile) string {
	var hops []string
	for _, p := range paths {
		if p.Server.Kind == "exit" {
			hops = append(hops, "direct")
		} else {
			hops = append(hops, p.Server.Label)
		}
	}
	return "AUTO " + paths[0].Exit.Label + " · " + strings.Join(hops, " → ")
}

// dnsServerIPs достаёт из dns-конфига транспорта только литеральные IP —
// на них строится direct-правило для DNS. Понимает две формы записи:
// "1.1.1.1" и "https://1.1.1.1/dns-query" (DoH по IP: tcp/443 до резолвера
// не душится DPI-сетями, в отличие от udp/53 — инцидент 9.10: провайдер
// резал зарубежный UDP 53, plain-DNS умирал целиком). DoH-URL с доменом
// (https://cloudflare-dns.com/...) не подходит — требует бутстрап-резолва
// и отсекается vpn validate.
func dnsServerIPs(r *registry.Registry) []string {
	seen := map[string]bool{}
	var ips []string
	for _, s := range r.Transport.DNS {
		s = strings.TrimSpace(s)
		if u, err := url.Parse(s); err == nil && u.Host != "" {
			s = u.Hostname() // https://<ip>/dns-query → <ip>
		}
		if ip := net.ParseIP(s); ip != nil && !seen[ip.String()] {
			seen[ip.String()] = true
			ips = append(ips, ip.String())
		}
	}
	return ips
}

// FailoverConfig builds one full client config that tries the paths strictly in
// order. Xray has no priority strategy (XTLS/Xray-core#3114, declined), so this
// uses the official workaround: one balancer per hop, chained through
// fallbackTag to a loopback outbound that re-enters routing at the next
// balancer. burstObservatory health-checks every hop; when all are dead the
// chain ends in "block" (no direct leak).
func FailoverConfig(r *registry.Registry, paths []Profile, socksPort int, rp registry.RoutingProfile) ([]byte, error) {
	var outbounds []obj
	var balancers []obj
	var chainRules []obj
	// selector в xray — префикс, не точное совпадение: "proxy-1" поймал бы и
	// "proxy-10". Девять релеев на один выход — предел, дальше падаем громко.
	if len(paths) > 9 {
		return nil, fmt.Errorf("failover: %d путей — максимум 9 (префиксы тегов конфликтуют)", len(paths))
	}
	for i, p := range paths {
		n := i + 1
		tag := fmt.Sprintf("proxy-%d", n)
		outbounds = append(outbounds, proxyOutboundTag(r, p, tag))
		fo := obj{
			"tag":      fmt.Sprintf("fo-%d", n),
			"selector": []string{tag},
			"strategy": obj{"type": "leastPing"},
		}
		if i == len(paths)-1 {
			fo["fallbackTag"] = "block"
		} else {
			// Падение hop-а N → loopback → повторный вход в роутинг → balancer N+1.
			lt := fmt.Sprintf("loop-%d", n+1)
			ib := fmt.Sprintf("ilb-%d", n+1)
			fo["fallbackTag"] = lt
			outbounds = append(outbounds, obj{"tag": lt, "protocol": "loopback", "settings": obj{"inboundTag": ib}})
			chainRules = append(chainRules, obj{"type": "field", "inboundTag": []string{ib}, "balancerTag": fmt.Sprintf("fo-%d", n+1)})
		}
		balancers = append(balancers, fo)
	}
	outbounds = append(outbounds,
		obj{"tag": "direct", "protocol": "freedom"},
		obj{"tag": "fragment", "protocol": "freedom", "settings": obj{"fragment": r.Transport.Fragment}},
		obj{"tag": "block", "protocol": "blackhole"},
	)
	// DNS первым правилом — в direct, мимо балансера: правило теперь эмитится
	// в routingRules для ВСЕХ клиентских конфигов (история и обоснование —
	// комментарий в happ.go routingRules). Цепочные правила идут следом.
	rules := routingRules(r, rp, obj{"balancerTag": "fo-1"}, chainRules...)
	cfg := obj{
		"remarks": failoverName(paths),
		"log":     obj{"loglevel": "warning"},
		"dns":     obj{"servers": r.Transport.DNS, "queryStrategy": "UseIPv4"},
		"inbounds": []obj{{
			"tag": "socks", "listen": "127.0.0.1", "port": socksPort, "protocol": "socks",
			"settings": obj{"udp": true, "auth": "noauth"},
			"sniffing": obj{"enabled": true, "destOverride": []string{"http", "tls", "quic"}, "routeOnly": true},
		}},
		"outbounds": outbounds,
		"routing": obj{
			"domainStrategy": "IPIfNonMatch",
			"balancers":      balancers,
			"rules":          rules,
		},
		"burstObservatory": obj{
			"subjectSelector": []string{"proxy-"},
			"pingConfig": obj{
				"destination":   "http://www.gstatic.com/generate_204",
				"connectivity":  "http://www.gstatic.com/generate_204",
				"interval":      "30s",
				"timeout":       "5s",
				"sampling":      2,
			},
		},
		"stats": obj{},
	}
	return json.Marshal(cfg)
}
