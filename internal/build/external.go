package build

import (
	"encoding/json"
	"fmt"
	"github.com/OXI-717/ai-agents-relay-kit/internal/external"
	"strconv"
	"strings"
)

// LinkOutbound turns a third-party vless:// link into a "proxy" outbound for full-JSON clients.
// Errors never include the link itself: it carries the owner's UUID.
func LinkOutbound(link string) (obj, string, error) {
	u, err := external.ParseEndpoint(link)
	if err != nil {
		return nil, "", fmt.Errorf("invalid external link at line 1")
	}
	id := u.User.Username()
	if id == "" {
		return nil, "", fmt.Errorf("invalid external link at line 1")
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil {
		return nil, "", fmt.Errorf("invalid external link at line 1")
	}
	q := u.Query()
	user := obj{"id": id, "encryption": "none"}
	if f := q.Get("flow"); f != "" {
		user["flow"] = f
	}

	network := q.Get("type")
	if network == "" {
		network = "tcp"
	}
	ss := obj{"network": network}
	switch network {
	case "tcp", "raw":
		if q.Get("headerType") == "http" {
			ss["tcpSettings"] = obj{"header": obj{"type": "http"}}
		}
	case "xhttp", "splithttp":
		ss["network"] = "xhttp"
		x := obj{"path": q.Get("path"), "mode": orDefault(q.Get("mode"), "auto")}
		if h := q.Get("host"); h != "" {
			x["host"] = h
		}
		if e := q.Get("extra"); e != "" {
			var extra obj
			if err := json.Unmarshal([]byte(e), &extra); err != nil {
				return nil, "", fmt.Errorf("invalid external link at line 1")
			}
			x["extra"] = extra
		}
		ss["xhttpSettings"] = x
	case "ws":
		ss["wsSettings"] = obj{"path": q.Get("path"), "headers": obj{"Host": q.Get("host")}}
	case "grpc":
		ss["grpcSettings"] = obj{"serviceName": q.Get("serviceName")}
	default:
		return nil, "", fmt.Errorf("invalid external link at line 1")
	}

	switch sec := orDefault(q.Get("security"), "none"); sec {
	case "reality":
		if q.Get("pbk") == "" {
			return nil, "", fmt.Errorf("invalid external link at line 1")
		}
		ss["security"] = "reality"
		ss["realitySettings"] = obj{
			"serverName": q.Get("sni"), "fingerprint": orDefault(q.Get("fp"), "chrome"),
			"publicKey": q.Get("pbk"), "shortId": q.Get("sid"), "spiderX": orDefault(q.Get("spx"), "/"),
		}
	case "tls":
		tls := obj{"serverName": q.Get("sni"), "fingerprint": orDefault(q.Get("fp"), "chrome")}
		if a := q.Get("alpn"); a != "" {
			tls["alpn"] = strings.Split(a, ",")
		}
		ss["security"] = "tls"
		ss["tlsSettings"] = tls
	case "none":
		ss["security"] = "none"
	default:
		return nil, "", fmt.Errorf("invalid external link at line 1")
	}

	name := u.Fragment
	if name == "" {
		name = u.Hostname()
	}
	return obj{
		"tag": "proxy", "protocol": "vless",
		"settings":       obj{"vnext": []obj{{"address": u.Hostname(), "port": port, "users": []obj{user}}}},
		"streamSettings": ss,
	}, name, nil
}

func orDefault(v, d string) string {
	if v == "" {
		return d
	}
	return v
}
