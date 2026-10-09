package verify

import "testing"

func TestCheckIP(t *testing.T) {
	if err := checkIP("192.0.2.10\n", "192.0.2.10"); err != nil {
		t.Fatal(err)
	}
	if err := checkIP("203.0.113.5", "192.0.2.10"); err == nil {
		t.Fatal("mismatch accepted")
	}
}

func TestFreePort(t *testing.T) {
	p, err := FreePort()
	if err != nil || p < 1024 {
		t.Fatalf("port %d err %v", p, err)
	}
}
