package xraystats

import (
	"context"
	"testing"
)

func encStat(name string, value int64) []byte {
	return appendFieldVarint(appendFieldString(nil, 1, name), 2, uint64(value))
}

func TestCodecRoundTrip(t *testing.T) {
	// hand-encoded QueryStatsResponse { stat { name, value } x2 }
	msg := appendFieldBytes(nil, 1, encStat("user>>>a@kz>>>traffic>>>uplink", 100))
	msg = appendFieldBytes(msg, 1, encStat("user>>>a@kz>>>traffic>>>downlink", 7))
	got, err := decQueryStats(msg)
	if err != nil {
		t.Fatal(err)
	}
	if got["user>>>a@kz>>>traffic>>>uplink"] != 100 || got["user>>>a@kz>>>traffic>>>downlink"] != 7 {
		t.Fatalf("got %v", got)
	}
}

func TestQueryStatsRequestFrame(t *testing.T) {
	req := encQueryStats("user>>>", false)
	if req[0] != 0 || len(req) < 6 {
		t.Fatalf("bad frame %v", req)
	}
	fs, err := parseFields(req[5:])
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 || fs[0].num != 1 || string(fs[0].data) != "user>>>" || fs[1].num != 2 {
		t.Fatalf("fields %v", fs)
	}
}

func TestDecSysStats(t *testing.T) {
	var m []byte
	m = appendFieldVarint(m, 1, 42)  // goroutines
	m = appendFieldVarint(m, 3, 1<<20) // alloc
	m = appendFieldVarint(m, 9, 600) // uptime
	s, err := decSysStats(m)
	if err != nil {
		t.Fatal(err)
	}
	if s.NumGoroutine != 42 || s.Alloc != 1<<20 || s.Uptime != 600 {
		t.Fatalf("%+v", s)
	}
}

func TestDecOnlineIPs(t *testing.T) {
	var ips []byte // IPList { repeated bytes ip = 1 }
	ips = appendFieldBytes(ips, 1, []byte{1, 2, 3, 4})
	ips = appendFieldBytes(ips, 1, []byte{5, 6, 7, 8})
	entry := appendFieldBytes(appendFieldString(nil, 1, "a@kz"), 2, ips)
	msg := appendFieldBytes(nil, 1, entry)
	n, err := decOnlineIPs(msg)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("online=%d", n)
	}
}

func TestClientUsesInvoker(t *testing.T) {
	c := &Client{Invoke: func(ctx context.Context, method string, req []byte) ([]byte, error) {
		if method != "QueryStats" {
			t.Fatalf("method %s", method)
		}
		return appendFieldBytes(nil, 1, encStat("x", 5)), nil
	}}
	m, err := c.QueryStats(context.Background(), "user>>>")
	if err != nil || m["x"] != 5 {
		t.Fatalf("%v %v", m, err)
	}
}
