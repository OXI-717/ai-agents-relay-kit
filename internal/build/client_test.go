package build

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func TestVlessLinkParams(t *testing.T) {
	r := load(t)
	ps, err := Profiles(r, r.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	link := VlessLink(r, ps[0])
	u, err := url.Parse(link)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "vless" || u.User.Username() != "11111111-1111-4111-8111-111111111111" || u.Host != "192.0.2.10:443" {
		t.Fatalf("bad link %s", link)
	}
	q := u.Query()
	want := map[string]string{"type": "xhttp", "security": "reality", "path": "/kzpath", "mode": "stream-one",
		"sni": "www.example.com", "pbk": "TESTPUBKZ", "sid": "0a1b2c3d", "fp": "chrome", "encryption": "none",
		// INCY share-link fragmentation params (docs.incy.cc/en/share-links)
		"fragmentPackets": "tlshello", "fragmentLength": "100-200", "fragmentInterval": "10-20"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s=%q want %q", k, q.Get(k), v)
		}
	}
	var extra map[string]any
	if err := json.Unmarshal([]byte(q.Get("extra")), &extra); err != nil || extra["xmux"] == nil {
		t.Fatalf("extra %q: %v", q.Get("extra"), err)
	}
}

func TestLinkFragmentEncoding(t *testing.T) {
	r := load(t)
	ps, _ := Profiles(r, r.Users[0])
	p := ps[0]
	p.Name = "Казахстан · 1"
	u, err := url.Parse(VlessLink(r, p))
	if err != nil || u.Fragment != "Казахстан · 1" {
		t.Fatalf("fragment %q err %v", u.Fragment, err)
	}
}

func decodeIncy(t *testing.T, b []byte) []string {
	t.Helper()
	raw, err := base64.StdEncoding.DecodeString(string(b))
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func TestIncySubscription(t *testing.T) {
	r := load(t)
	b, err := IncySubscription(r, r.Users[0], 1790000000)
	if err != nil {
		t.Fatal(err)
	}
	var cfgs []map[string]any
	if err := json.Unmarshal(b, &cfgs); err != nil {
		t.Fatal(err)
	}
	// alice: kz, am (без релеев — failover-групп нет) + external ext-one
	if len(cfgs) != 3 {
		t.Fatalf("configs %d", len(cfgs))
	}
	if cfgs[0]["remarks"] != "KZ" || cfgs[1]["remarks"] != "AM" {
		t.Fatalf("remarks %v %v", cfgs[0]["remarks"], cfgs[1]["remarks"])
	}
	if strings.Contains(string(b), "incy://routing") {
		t.Fatal("routing line in JSON body: должен идти заголовком воркера")
	}
	rl, err := IncyRoutingLink(r, r.Users[0], 1790000000)
	if err != nil {
		t.Fatal(err)
	}
	rj, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(rl, "incy://routing/onadd/"))
	var prof map[string]any
	if err := json.Unmarshal(rj, &prof); err != nil {
		t.Fatal(err)
	}
	if prof["Name"] != "UNITE" || prof["LastUpdated"] != "1790000000" || prof["FakeDNS"] != "false" {
		t.Fatalf("profile %v", prof)
	}
	golden(t, "incy-alice.json", append(b, '\n'))
}

func TestIncyBobNoExternal(t *testing.T) {
	r := load(t)
	b, _ := IncySubscription(r, r.Users[1], 1790000000)
	var cfgs []map[string]any
	if err := json.Unmarshal(b, &cfgs); err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 1 { // kz
		t.Fatalf("bob configs %d", len(cfgs))
	}
}

func TestHappSubscription(t *testing.T) {
	r := load(t)
	b, err := HappSubscription(r, r.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	var cfgs []map[string]any
	if err := json.Unmarshal(b, &cfgs); err != nil {
		t.Fatal(err)
	}
	if len(cfgs) != 3 { // kz, am + external ext-one (shared with alice)
		t.Fatalf("configs %d", len(cfgs))
	}
	if cfgs[0]["remarks"] != "KZ" || cfgs[0]["dns"] == nil || cfgs[0]["routing"] == nil {
		t.Fatalf("cfg0 %v", cfgs[0])
	}
	if strings.Contains(string(b), "fakedns") {
		t.Fatal("fakedns present")
	}
	golden(t, "happ-alice.json", b)
}

func TestSubscriptionSizes(t *testing.T) {
	r := load(t)
	incy, _ := IncySubscription(r, r.Users[0], 1790000000)
	happ, _ := HappSubscription(r, r.Users[0])
	if len(incy) > 64*1024 || len(happ) > 64*1024 {
		t.Fatalf("too big: incy %d happ %d", len(incy), len(happ))
	}
}

func TestSingleConfigDNSDirectFirst(t *testing.T) {
	r := load(t)
	ps, err := Profiles(r, r.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	b, err := ClientConfig(r, ps[0], 10808, r.Routing[0])
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		t.Fatal(err)
	}
	rules := cfg["routing"].(map[string]any)["rules"].([]any)
	// Инцидент 9.10: в одиночных конфигах DNS ловился catch-all-ом и умирал
	// вместе с прокси-хопом → блэкаут всего интернета при полумёртвом канале.
	r0 := rules[0].(map[string]any)
	if _, ok := r0["ip"]; !ok || r0["outboundTag"] != "direct" {
		t.Fatalf("первое правило не DNS→direct: %v", r0)
	}
	// DoH-по-IP и plain-записи дают одинаковый набор IP без дублей.
	got := fmt.Sprint(r0["ip"])
	if got != "[1.1.1.1 8.8.8.8]" {
		t.Fatalf("dns ip правило %v, ждём [1.1.1.1 8.8.8.8]", r0["ip"])
	}
	// DoH-URL резолверы попадают в dns.servers как есть.
	dns := fmt.Sprint(cfg["dns"].(map[string]any)["servers"])
	if !strings.Contains(dns, "https://1.1.1.1/dns-query") {
		t.Fatalf("dns servers без DoH: %v", dns)
	}
}

func TestBundle(t *testing.T) {
	r := load(t)
	txt, png, err := Bundle(r, r.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(txt), "vless://") || len(png) < 100 || string(png[1:4]) != "PNG" {
		t.Fatal("bad bundle")
	}
}
