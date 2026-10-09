package build

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestLinkOutboundRealityTCP(t *testing.T) {
	out, name, err := LinkOutbound("vless://66666666-6666-4666-8666-666666666666@198.51.100.1:443?encryption=none&security=reality&sni=vk.com&fp=chrome&pbk=EXTPBK&sid=01&type=tcp&flow=xtls-rprx-vision&spx=%2F#OM-VK")
	if err != nil {
		t.Fatal(err)
	}
	if name != "OM-VK" {
		t.Fatalf("name %q", name)
	}
	b, _ := json.Marshal(out)
	for _, want := range []string{`"address":"198.51.100.1"`, `"port":443`, `"flow":"xtls-rprx-vision"`, `"network":"tcp"`, `"security":"reality"`, `"serverName":"vk.com"`, `"publicKey":"EXTPBK"`, `"shortId":"01"`, `"fingerprint":"chrome"`, `"tag":"proxy"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
	if strings.Contains(string(b), "dialerProxy") {
		t.Error("fragment must not be applied to external servers")
	}
}

func TestLinkOutboundXHTTPTLS(t *testing.T) {
	out, _, err := LinkOutbound("vless://66666666-6666-4666-8666-666666666666@example.org:8443?security=tls&sni=example.org&alpn=h2%2Chttp%2F1.1&type=xhttp&path=%2Fx&host=example.org&mode=packet-up#X")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(out)
	for _, want := range []string{`"network":"xhttp"`, `"path":"/x"`, `"mode":"packet-up"`, `"host":"example.org"`, `"security":"tls"`, `"alpn":["h2","http/1.1"]`, `"port":8443`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("missing %s in %s", want, b)
		}
	}
}

func TestLinkOutboundErrors(t *testing.T) {
	for _, link := range []string{
		"vmess://abc",
		"vless://66666666-6666-4666-8666-666666666666@198.51.100.1:443?type=kcp#K",
		"vless://66666666-6666-4666-8666-666666666666@198.51.100.1:443?security=reality&type=tcp#NoKey",
		"vless://@198.51.100.1:443?type=tcp#NoUser",
		"vless://66666666-6666-4666-8666-666666666666@198.51.100.1?type=tcp#NoPort",
	} {
		if _, _, err := LinkOutbound(link); err == nil {
			t.Errorf("accepted %s", link)
		} else if strings.Contains(err.Error(), "66666666") {
			t.Errorf("error leaks uuid: %v", err)
		}
	}
}

func TestHappIncludesSharedExternal(t *testing.T) {
	r := load(t)
	var alice, bob []map[string]any
	b, err := HappSubscription(r, r.Users[0])
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal(b, &alice)
	b, _ = HappSubscription(r, r.Users[1])
	_ = json.Unmarshal(b, &bob)
	if len(alice) != 3 || alice[2]["remarks"] != "ext · one" || alice[2]["routing"] == nil || alice[2]["dns"] == nil {
		t.Fatalf("alice %d configs, last %v", len(alice), alice[len(alice)-1]["remarks"])
	}
	if len(bob) != 1 {
		t.Fatalf("bob got %d configs, external leaked?", len(bob))
	}
}

func TestLinkOutboundErrorDoesNotLeakAnyInput(t *testing.T) {
	marker := "deadbeef-1234-4567-8901-abcdef012345"
	for _, link := range []string{
		"vless://" + marker + "@example.org:bad",
		"vless://@example.org:443#" + marker,
		"vless://" + marker + "@example.org:443?type=" + marker,
		"vless://" + marker + "@example.org:443?security=" + marker,
		"vless://" + marker + "@example.org:443?type=xhttp&extra=bad#" + marker,
	} {
		_, _, err := LinkOutbound(link)
		if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "line 1") {
			t.Fatalf("unsafe error: %v", err)
		}
	}
}

func TestLinkOutboundRejectsInvalidEndpoint(t *testing.T) {
	for _, authority := range []string{"not-uuid@example.org:443", "66666666-6666-4666-8666-666666666666@:443", "66666666-6666-4666-8666-666666666666@bad_host:443", "66666666-6666-4666-8666-666666666666@-bad.org:443", "66666666-6666-4666-8666-666666666666@example.org:0", "66666666-6666-4666-8666-666666666666@example.org:65536"} {
		if _, _, err := LinkOutbound("vless://" + authority); err == nil {
			t.Errorf("invalid endpoint accepted: %s", authority)
		}
	}
}
