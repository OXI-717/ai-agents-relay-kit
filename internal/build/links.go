package build

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
)

type Profile struct {
	Key    string
	Exit   registry.Server
	Name   string
	Server registry.Server
	UUID   string
}

func Profiles(r *registry.Registry, u registry.User) ([]Profile, error) {
	var out []Profile
	for _, pair := range r.PairsFor(u) {
		s, k := pair.Entry, pair.Key
		id := r.Secrets.UUIDs[k]
		if id == "" {
			return nil, fmt.Errorf("%s: no UUID (run: vpn uuids fill)", k)
		}
		name := s.Label
		if s.Kind == "relay" {
			name += " → " + pair.Exit.Label
		}
		out = append(out, Profile{Key: k, Exit: pair.Exit, Name: name, Server: s, UUID: id})
	}
	return out, nil
}

func VlessLink(r *registry.Registry, p Profile) string {
	sec := r.Secrets.Servers[p.Server.ID]
	extra, _ := json.Marshal(obj{"xmux": r.Transport.Xmux})
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("type", "xhttp")
	q.Set("path", sec.XHTTPPath)
	q.Set("mode", r.Transport.ClientMode)
	q.Set("security", "reality")
	q.Set("sni", p.Server.Reality.ServerNames[0])
	q.Set("fp", "chrome")
	q.Set("pbk", p.Server.Reality.PublicKey)
	q.Set("sid", sec.ShortID)
	q.Set("spx", "/")
	q.Set("extra", string(extra))
	// INCY share-links (docs.incy.cc/en/share-links): per-server TCP fragmentation
	// is passed as fragmentPackets/fragmentLength/fragmentInterval query params.
	if frag := r.Transport.Fragment; len(frag) > 0 {
		q.Set("fragmentPackets", frag["packets"])
		q.Set("fragmentLength", frag["length"])
		q.Set("fragmentInterval", frag["interval"])
	}
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(p.UUID),
		Host:     fmt.Sprintf("%s:%d", p.Server.Host, p.Server.Port),
		RawQuery: q.Encode(),
		Fragment: p.Name,
	}
	return u.String()
}
