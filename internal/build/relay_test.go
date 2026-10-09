package build

import (
	"encoding/json"
	"fmt"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"strings"
	"testing"
)

func relayRegistry(t *testing.T) *registry.Registry {
	r := load(t)
	s := r.Servers[0]
	s.ID = "tw"
	s.Label = "TW"
	s.Kind = "relay"
	s.Host = "192.0.2.30"
	s.Exits = []string{"am", "kz"}
	r.Servers = append(r.Servers, s)
	r.Secrets.Servers["tw"] = r.Secrets.Servers["kz"]
	for i, k := range []string{"alice@tw/am", "alice@tw/kz", "svc:tw>am", "svc:tw>kz"} {
		r.Secrets.UUIDs[k] = []string{"66666666-6666-4666-8666-666666666666", "77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888", "99999999-9999-4999-8999-999999999999"}[i]
	}
	return r
}

func TestRelayServer(t *testing.T) {
	r := relayRegistry(t)
	s, _ := r.ServerByID("tw")
	b, err := ServerConfig(r, s)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err = json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"alice@tw/am", "alice@tw/kz", "via-am", "via-kz", r.Secrets.UUIDs["svc:tw>am"]} {
		if !strings.Contains(string(b), want) {
			t.Fatalf("missing %s", want)
		}
	}
	if strings.Contains(string(b), "fragment") || strings.Contains(string(b), "bob@") {
		t.Fatal("unexpected relay client or fragment")
	}
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	if rules[len(rules)-1].(map[string]any)["outboundTag"] != "block" {
		t.Fatal("must fail closed")
	}
	golden(t, "server-tw.json", b)
}

func TestExitServiceClient(t *testing.T) {
	r := relayRegistry(t)
	s, _ := r.ServerByID("am")
	b, err := ServerConfig(r, s)
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	json.Unmarshal(b, &cfg)
	found := false
	for _, v := range cfg["routing"].(map[string]any)["rules"].([]any) {
		rule := v.(map[string]any)
		if us, ok := rule["user"].([]any); ok {
			for _, u := range us {
				if u == "svc:tw>am" {
					found = true
					if rule["outboundTag"] != "direct" {
						t.Fatal("service must exit directly")
					}
				}
			}
		}
	}
	if !found {
		t.Fatal("no explicit service route")
	}
	golden(t, "server-am-service.json", b)
	delete(r.Secrets.UUIDs, "svc:tw>am")
	if _, err := ServerConfig(r, s); err == nil {
		t.Fatal("missing service UUID accepted")
	}
}

func TestRelaySubscriptions(t *testing.T) {
	r := relayRegistry(t)
	u := r.Users[0]
	b, err := IncySubscription(r, u, 1790000000)
	if err != nil {
		t.Fatal(err)
	}
	var cfgs []map[string]any
	if err := json.Unmarshal(b, &cfgs); err != nil {
		t.Fatal(err)
	}
	// 2 failover-цепочки (KZ и AM: TW → direct) + kz, am, TW→am, TW→kz + external
	if len(cfgs) != 7 {
		t.Fatalf("configs %d", len(cfgs))
	}
	var foKZ, foAM map[string]any
	for _, c := range cfgs {
		switch c["remarks"] {
		case "AUTO KZ · TW → direct":
			foKZ = c
		case "AUTO AM · TW → direct":
			foAM = c
		}
	}
	if foKZ == nil || foAM == nil {
		t.Fatalf("failover configs missing: first=%v", cfgs[0]["remarks"])
	}
	for _, name := range []string{"kz", "am"} {
		c := foKZ
		if name == "am" {
			c = foAM
		}
		balancers := c["routing"].(map[string]any)["balancers"].([]any)
		if len(balancers) != 2 {
			t.Fatalf("%s: balancers %d", name, len(balancers))
		}
		fo1 := balancers[0].(map[string]any)
		if fo1["fallbackTag"] != "loop-2" {
			t.Fatalf("%s: fo-1 fallback %v", name, fo1["fallbackTag"])
		}
		if balancers[1].(map[string]any)["fallbackTag"] != "block" {
			t.Fatalf("%s: последний hop должен падать в block (fail-closed)", name)
		}
		tags := map[string]bool{}
		for _, o := range c["outbounds"].([]any) {
			tags[o.(map[string]any)["tag"].(string)] = true
		}
		for _, want := range []string{"proxy-1", "proxy-2", "loop-2", "direct", "block"} {
			if !tags[want] {
				t.Fatalf("%s: нет outbound %s (%v)", name, want, tags)
			}
		}
		obs := c["burstObservatory"].(map[string]any)
		if ss := obs["subjectSelector"].([]any); ss[0] != "proxy-" {
			t.Fatalf("%s: observatory subject %v", name, ss)
		}
		rules := c["routing"].(map[string]any)["rules"].([]any)
		// правило DNS → direct обязано стоять первым: в TUN системный DNS не
		// должен попадать в балансер (инцидент 8.10)
		first := rules[0].(map[string]any)
		if _, ok := first["ip"]; !ok || first["outboundTag"] != "direct" {
			t.Fatalf("%s: DNS-direct правило не первым: %v", name, first)
		}
		if _, ok := rules[1].(map[string]any)["inboundTag"]; !ok {
			t.Fatalf("%s: ilb-правило не вторым: %v", name, rules[1])
		}
		if rules[len(rules)-1].(map[string]any)["balancerTag"] != "fo-1" {
			t.Fatalf("%s: catch-all не в балансер: %v", name, rules[len(rules)-1])
		}
		raw, _ := json.Marshal(c)
		if !strings.Contains(string(raw), r.Secrets.UUIDs["alice@tw/"+name]) ||
			!strings.Contains(string(raw), r.Secrets.UUIDs["alice@"+name]) {
			t.Fatalf("%s: UUID хопов не в конфиге", name)
		}
	}
	golden(t, "incy-alice-relay.json", append(b, '\n'))
	hb, err := HappSubscription(r, u)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(hb), "TW → AM") || !strings.Contains(string(hb), "TW → KZ") {
		t.Fatal("missing relay profiles")
	}
	if !strings.Contains(string(hb), "AUTO AM") {
		t.Fatal("happ без failover-конфига")
	}
	golden(t, "happ-alice-relay.json", hb)
}

// 3-хоповая цепочка (два релея + direct) — самый хрупкий кусок генератора:
// две пары loopback-переходов, три балансера, финал в block (ревью 8.10).
func TestFailoverThreeHops(t *testing.T) {
	r := relayRegistry(t)
	s2 := r.Servers[0]
	s2.ID = "tw2"
	s2.Label = "TW2"
	s2.Kind = "relay"
	s2.Host = "192.0.2.31"
	s2.Exits = []string{"am"}
	r.Servers = append(r.Servers, s2)
	r.Secrets.Servers["tw2"] = r.Secrets.Servers["kz"]
	r.Secrets.UUIDs["alice@tw2/am"] = "aaaa2222-2222-4222-8222-222222222222"

	groups, err := FailoverGroups(r, r.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	var am []Profile
	for _, g := range groups {
		if g[0].Exit.ID == "am" {
			am = g
		}
	}
	if len(am) != 3 {
		t.Fatalf("am group %d путей, ждём 3", len(am))
	}
	b, err := FailoverConfig(r, am, 10809, r.Routing[0])
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	balancers := cfg["routing"].(map[string]any)["balancers"].([]any)
	if len(balancers) != 3 {
		t.Fatalf("balancers %d", len(balancers))
	}
	for i, wantFallback := range []any{"loop-2", "loop-3", "block"} {
		if balancers[i].(map[string]any)["fallbackTag"] != wantFallback {
			t.Fatalf("fo-%d fallback %v, ждём %v", i+1, balancers[i].(map[string]any)["fallbackTag"], wantFallback)
		}
	}
	tags := map[string]bool{}
	for _, o := range cfg["outbounds"].([]any) {
		tags[o.(map[string]any)["tag"].(string)] = true
	}
	for _, want := range []string{"proxy-1", "proxy-2", "proxy-3", "loop-2", "loop-3"} {
		if !tags[want] {
			t.Fatalf("нет outbound %s", want)
		}
	}
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	if _, ok := rules[0].(map[string]any)["ip"]; !ok {
		t.Fatal("DNS-правило не первым")
	}
	for _, i := range []int{1, 2} {
		if _, ok := rules[i].(map[string]any)["inboundTag"]; !ok {
			t.Fatalf("ilb-правило rules[%d] отсутствует", i)
		}
	}
	raw, _ := json.Marshal(cfg)
	for _, uuid := range []string{"66666666-6666-4666-8666-666666666666", r.Secrets.UUIDs["alice@tw2/am"]} {
		if !strings.Contains(string(raw), uuid) {
			t.Fatalf("нет UUID %s", uuid)
		}
	}
	golden(t, "chain-am-3hop.json", b)
}

// selector в xray — префикс: "proxy-1" поймал бы и "proxy-10". Громко падаем
// вместо тихой порчи приоритета (ревью 8.10).
func TestFailoverTooManyPaths(t *testing.T) {
	r := load(t)
	var paths []Profile
	for i := 0; i < 10; i++ {
		s := r.Servers[0]
		s.ID = fmt.Sprintf("r%d", i)
		s.Kind = "relay"
		paths = append(paths, Profile{Key: fmt.Sprintf("k%d", i), Exit: s, Name: s.ID, Server: s, UUID: "00000000-0000-4000-8000-000000000000"})
	}
	if _, err := FailoverConfig(r, paths, 10809, r.Routing[0]); err == nil {
		t.Fatal(">9 путей должен давать ошибку")
	}
}
