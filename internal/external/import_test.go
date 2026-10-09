package external

import (
	"strings"
	"testing"
)

func TestParseLinks(t *testing.T) {
	text := "garbage\nvless://66666666-6666-4666-8666-666666666666@198.51.100.1:443?security=reality&type=tcp#OM-VK-RealityB\n  vless://77777777-7777-4777-8777-777777777777@198.51.100.2:8443?type=tcp#%D0%A2%D0%B5%D1%81%D1%82\nvmess://abc\n"
	got, err := ParseLinks(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d", len(got))
	}
	if got[0].ID != "om-vk-realityb" || got[0].Label != "OM-VK-RealityB" || got[0].Host != "198.51.100.1" {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Label != "Тест" || got[1].ID == "" {
		t.Fatalf("%+v", got[1])
	}
}

func TestParseLinksErrorDoesNotLeak(t *testing.T) {
	marker := "deadbeef-1234-4567-8901-abcdef012345"
	_, err := ParseLinks("ignored\nvless://" + marker + "@example.org:bad#" + marker)
	if err == nil || strings.Contains(err.Error(), marker) || !strings.Contains(err.Error(), "line 2") {
		t.Fatalf("unsafe error: %v", err)
	}
}

func TestParseLinksRejectsInvalidEndpoint(t *testing.T) {
	for _, authority := range []string{"not-uuid@example.org:443", "66666666-6666-4666-8666-666666666666@:443", "66666666-6666-4666-8666-666666666666@bad_host:443", "66666666-6666-4666-8666-666666666666@-bad.org:443", "66666666-6666-4666-8666-666666666666@example.org:0", "66666666-6666-4666-8666-666666666666@example.org:65536"} {
		if _, err := ParseLinks("vless://" + authority + "#test"); err == nil {
			t.Errorf("invalid endpoint accepted: %s", authority)
		}
	}
}
func TestParseLinksRejectsDuplicateIDs(t *testing.T) {
	link := "vless://66666666-6666-4666-8666-666666666666@example.org:443#same"
	if _, err := ParseLinks(link + "\n" + link); err == nil {
		t.Fatal("duplicate imported")
	}
}
