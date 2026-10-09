package deploy

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestKVKey(t *testing.T) {
	k := KVKey(strings.Repeat("a", 40), "incy")
	if !strings.HasPrefix(k, "sub:") || !strings.HasSuffix(k, ":incy") || strings.Contains(k, "aaaa") || len(k) != len("sub:")+64+len(":incy") {
		t.Fatalf("key %s", k)
	}
}

func TestPlanKV(t *testing.T) {
	put, keep, err := PlanKV(testReg(t), 1790000000)
	if err != nil {
		t.Fatal(err)
	}
	// alice incy+happ (обе с routing-заголовком), bob incy(+routing)
	if len(put) != 6 || len(keep) != 6 {
		t.Fatalf("put %d keep %d", len(put), len(keep))
	}
	for _, e := range put {
		if strings.HasSuffix(e.Key, ":routing") {
			continue
		}
		if e.Metadata["title"] == "" || e.Metadata["format"] == "" {
			t.Fatalf("metadata %v", e.Metadata)
		}
	}
}

func TestPlanKVDeletesRevoked(t *testing.T) {
	r := testReg(t)
	_, keep, _ := PlanKV(r, 1)
	for k := range keep {
		if strings.Contains(k, KVKey("cccccccccccccccccccccccccccccccccccccccc", "incy")) {
			t.Fatal("revoked kept")
		}
	}
}

func TestPlanKVHappRoutingHeader(t *testing.T) {
	r := testReg(t)
	put, keep, err := PlanKV(r, 1790000000)
	if err != nil {
		t.Fatal(err)
	}
	alice := r.Secrets.Users["alice"].Token
	want := KVKey(alice, "happ") + ":routing"
	var got string
	for _, e := range put {
		if e.Key == want {
			got = e.Value
		}
		if e.Key == KVKey(alice, "incy")+":routing" {
			if !strings.HasPrefix(e.Value, "incy://routing/onadd/") || !keep[e.Key] {
				t.Fatalf("incy routing header bad: %q", e.Value)
			}
		}
	}
	if !strings.HasPrefix(got, "happ://routing/onadd/") || !keep[want] {
		t.Fatalf("routing header entry missing: %q", got)
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(got, "happ://routing/onadd/"))
	if err != nil || !strings.Contains(string(raw), `"Geositeurl":"https://github.com/Loyalsoldier`) || !strings.Contains(string(raw), `"LastUpdated":"1790000000"`) {
		t.Fatalf("bad profile: %v %s", err, raw)
	}
}
