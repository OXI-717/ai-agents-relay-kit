package registry

import (
	"strings"
	"testing"
)

func load(t *testing.T) *Registry {
	t.Helper()
	r, err := Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func hasErr(errs []error, sub string) bool {
	for _, e := range errs {
		if strings.Contains(e.Error(), sub) {
			return true
		}
	}
	return false
}

func TestValidateTestdataOK(t *testing.T) {
	if errs := load(t).Validate(); len(errs) != 0 {
		t.Fatalf("unexpected: %v", errs)
	}
}

func TestEntriesFor(t *testing.T) {
	r := load(t)
	var got []string
	for _, s := range r.EntriesFor(r.Users[0]) { // alice: все включённые
		got = append(got, s.ID)
	}
	if strings.Join(got, ",") != "kz,am" {
		t.Fatalf("alice entries %v", got)
	}
	got = nil
	for _, s := range r.EntriesFor(r.Users[1]) { // bob: только kz
		got = append(got, s.ID)
	}
	if strings.Join(got, ",") != "kz" {
		t.Fatalf("bob entries %v", got)
	}
}

func TestValidateMissingPairUUID(t *testing.T) {
	r := load(t)
	delete(r.Secrets.UUIDs, "alice@am")
	if !hasErr(r.Validate(), "alice@am: no UUID (run: vpn uuids fill)") {
		t.Fatal("missing uuid not reported")
	}
}

func TestValidateDuplicateUUID(t *testing.T) {
	r := load(t)
	r.Secrets.UUIDs["alice@am"] = r.Secrets.UUIDs["alice@kz"]
	if !hasErr(r.Validate(), "duplicate UUID") {
		t.Fatal("duplicate not reported")
	}
}

func TestValidateRevokedUUIDReused(t *testing.T) {
	r := load(t)
	r.Secrets.UUIDs["alice@am"] = r.Secrets.RevokedUUIDs[0]
	if !hasErr(r.Validate(), "revoked UUID reused") {
		t.Fatal("reuse not reported")
	}
}

func TestValidateRelay(t *testing.T) {
	for _, exit := range []string{"am", "off", "missing", "tw"} {
		t.Run(exit, func(t *testing.T) {
			r := load(t)
			relay := r.Servers[0]
			relay.ID = "tw"
			relay.Kind = "relay"
			relay.Exits = []string{exit}
			r.Servers = append(r.Servers, relay)
			r.Secrets.Servers["tw"] = r.Secrets.Servers["kz"]
			r.Secrets.UUIDs["alice@tw/"+exit] = "66666666-6666-4666-8666-666666666666"
			r.Secrets.UUIDs["svc:tw>"+exit] = "77777777-7777-4777-8777-777777777777"
			errs := r.Validate()
			if exit == "am" && len(errs) != 0 {
				t.Fatalf("valid relay rejected: %v", errs)
			}
			if exit != "am" && !hasErr(errs, "enabled exit") {
				t.Fatalf("invalid exit accepted: %v", errs)
			}
		})
	}
}

func TestValidateUnknownRefs(t *testing.T) {
	r := load(t)
	r.Users[1].Entries = []string{"nope"}
	r.Users[0].Routing = "nope"
	r.External[0].ShareWith = []string{"ghost"}
	errs := r.Validate()
	for _, want := range []string{"bob: unknown entry nope", "alice: unknown routing nope", "ext-one: share_with unknown user ghost"} {
		if !hasErr(errs, want) {
			t.Errorf("missing %q in %v", want, errs)
		}
	}
}

func TestValidateEnabledServerNeedsRealityAndSecrets(t *testing.T) {
	r := load(t)
	r.Servers[0].Reality.Target = ""
	delete(r.Secrets.Servers, "am")
	errs := r.Validate()
	if !hasErr(errs, "kz: reality.target empty (run: vpn server probe-target)") || !hasErr(errs, "am: missing server secrets") {
		t.Fatalf("got %v", errs)
	}
}

func TestValidateActiveUserNeedsToken(t *testing.T) {
	r := load(t)
	r.Secrets.Users["bob"] = UserSecrets{Token: "short"}
	if !hasErr(r.Validate(), "bob: token must be 40 hex") {
		t.Fatal("bad token accepted")
	}
}

func TestValidateGeoPins(t *testing.T) {
	r := load(t)
	r.Pins.GeoipURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
	r.Pins.GeositeSHA256 = "short"
	errs := r.Validate()
	if !hasErr(errs, "pins: geoip_url must pin a release asset") || !hasErr(errs, "pins: geosite_sha256 must be 64 hex") {
		t.Fatalf("got %v", errs)
	}
}

func TestValidateUnknownFormat(t *testing.T) {
	r := load(t)
	r.Users[0].Formats = []string{"clash"}
	if !hasErr(r.Validate(), "alice: unknown format clash") {
		t.Fatal("format accepted")
	}
}

func TestValidateRejectsUnsafeSlugs(t *testing.T) {
	for _, kind := range []string{"user", "server", "external"} {
		for _, id := range []string{"../escape", "", "UPPER", strings.Repeat("a", 33), "-bad"} {
			t.Run(kind+"/"+id, func(t *testing.T) {
				r := load(t)
				switch kind {
				case "user":
					r.Users[0].ID = id
				case "server":
					r.Servers[2].ID = id
				case "external":
					r.External[0].ID = id
				}
				if !hasErr(r.Validate(), "invalid "+kind+" slug") {
					t.Fatal("unsafe slug accepted")
				}
			})
		}
	}
}

func TestValidateDuplicateSubscriptionTokens(t *testing.T) {
	r := load(t)
	token := r.Secrets.Users["alice"].Token
	r.Secrets.Users["bob"] = UserSecrets{Token: token}
	errs := r.Validate()
	if !hasErr(errs, "duplicate subscription token") {
		t.Fatal("duplicate token accepted")
	}
	for _, e := range errs {
		if strings.Contains(e.Error(), token) {
			t.Fatal("token disclosed")
		}
	}
}

func TestValidateRelayRequiresUniqueExitsAndCredentials(t *testing.T) {
	for _, exits := range [][]string{nil, {"am", "am"}, {"am"}} {
		r := load(t)
		s := r.Servers[0]
		s.ID = "tw"
		s.Kind = "relay"
		s.Exits = exits
		r.Servers = append(r.Servers, s)
		r.Secrets.Servers["tw"] = r.Secrets.Servers["kz"]
		errs := r.Validate()
		switch len(exits) {
		case 0:
			if !hasErr(errs, "at least one enabled exit") {
				t.Fatal(errs)
			}
		case 2:
			if !hasErr(errs, "duplicate exit") {
				t.Fatal(errs)
			}
		case 1:
			for _, want := range []string{"alice@tw/am: no UUID", "svc:tw>am: no UUID"} {
				if !hasErr(errs, want) {
					t.Fatalf("missing %s: %v", want, errs)
				}
			}
		}
	}
	if PairKey("alice", "kz") != "alice@kz" || PairKey("alice", "tw", "am") != "alice@tw/am" {
		t.Fatal("key compatibility")
	}
}

func TestValidateNonDefaultPort(t *testing.T) {
	r := load(t)
	r.Servers[0].Port = 9443
	if errs := r.Validate(); len(errs) != 0 {
		t.Fatalf("port 9443 rejected: %v", errs)
	}
	for _, p := range []int{0, -1, 65536} {
		r.Servers[0].Port = p
		if !hasErr(r.Validate(), "kz: port must be 1-65535") {
			t.Errorf("port %d accepted", p)
		}
	}
}

func TestValidateRejectsXrayAPIPort(t *testing.T) {
	r := load(t)
	r.Servers[0].Port = XrayAPIPort
	if !hasErr(r.Validate(), "kz: port 10085 is reserved for the xray stats API") {
		t.Fatal("api port accepted")
	}
}
