package registry

import "testing"

func TestLoadTestdata(t *testing.T) {
	r, err := Load("../../testdata/registry")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Servers) != 3 || len(r.Users) != 3 || len(r.External) != 1 || len(r.Routing) != 1 {
		t.Fatalf("counts: %d servers %d users %d ext %d routing", len(r.Servers), len(r.Users), len(r.External), len(r.Routing))
	}
	if r.Secrets.Servers["kz"].ShortID != "0a1b2c3d" {
		t.Fatalf("secrets not loaded")
	}
	if r.Transport.ClientMode != "stream-one" || r.Pins.ServerImage == "" || r.Cloudflare.SubBaseURL == "" {
		t.Fatalf("transport/pins/cloudflare not loaded: %+v %+v %+v", r.Transport, r.Pins, r.Cloudflare)
	}
}
