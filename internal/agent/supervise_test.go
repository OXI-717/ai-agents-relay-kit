package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeHealth struct{ err error }

func (f fakeHealth) Alive(context.Context) error { return f.err }

type fakeHelper struct {
	statusOut   string
	statusErr   error
	activated   []string
	activateErr error
	noActivate  bool
}

func (f *fakeHelper) Status() (string, bool, error) {
	if f.statusErr != nil {
		return "", false, f.statusErr
	}
	cur, run := ParseHelperStatus(f.statusOut)
	return cur, run, nil
}

func (f *fakeHelper) Activate(id string) error {
	if f.activateErr != nil {
		return f.activateErr
	}
	f.activated = append(f.activated, id)
	return nil
}

func TestSuperviseHealthy(t *testing.T) {
	dir := t.TempDir()
	st := filepath.Join(dir, "supervise.json")
	os.WriteFile(st, []byte(`{"fails":1}`), 0o644)
	h := &fakeHelper{statusOut: "current=r1\ncontainer=running\n"}
	res := SuperviseOnce(context.Background(), fakeHealth{}, h, st, 2)
	if !res.Healthy || res.Fails != 0 || res.Restarted {
		t.Fatalf("res=%+v", res)
	}
	if len(h.activated) != 0 {
		t.Fatal("не должен рестартовать живой xray")
	}
	// счётчик сброшен
	if s := loadSuperviseState(st); s.Fails != 0 {
		t.Fatalf("fails not reset: %+v", s)
	}
}

func TestSuperviseTwoStrikesRestart(t *testing.T) {
	dir := t.TempDir()
	st := filepath.Join(dir, "supervise.json")
	dead := fakeHealth{err: errors.New("timeout")}
	h := &fakeHelper{statusOut: "current=rel-1\ncontainer=running\n"}
	// промах 1: копим
	res := SuperviseOnce(context.Background(), dead, h, st, 2)
	if res.Healthy || res.Fails != 1 || res.Restarted || len(h.activated) != 0 {
		t.Fatalf("strike1 res=%+v", res)
	}
	// промах 2: рестарт текущего релиза
	res = SuperviseOnce(context.Background(), dead, h, st, 2)
	if !res.Restarted || len(h.activated) == 0 {
		t.Fatalf("strike2 res=%+v activated=%v", res, h.activated)
	}
	if len(h.activated) != 1 || h.activated[0] != "rel-1" {
		t.Fatalf("activated=%v", h.activated)
	}
	if !res.Restarted {
		t.Fatalf("res.Restarted=false: %+v", res)
	}
}

func TestSuperviseNoCurrent(t *testing.T) {
	dir := t.TempDir()
	st := filepath.Join(dir, "supervise.json")
	dead := fakeHealth{err: errors.New("refused")}
	h := &fakeHelper{statusOut: "container=running\n"} // нет current=
	SuperviseOnce(context.Background(), dead, h, st, 2)
	SuperviseOnce(context.Background(), dead, h, st, 2)
	if len(h.activated) != 0 {
		t.Fatal("не должен активировать пустой релиз")
	}
}

func TestSuperviseHelperStatusFails(t *testing.T) {
	dir := t.TempDir()
	st := filepath.Join(dir, "supervise.json")
	dead := fakeHealth{err: errors.New("timeout")}
	h := &fakeHelper{statusErr: errors.New("sudo broken")}
	SuperviseOnce(context.Background(), dead, h, st, 2)
	res := SuperviseOnce(context.Background(), dead, h, st, 2)
	if res.Restarted || len(h.activated) != 0 {
		t.Fatalf("res=%+v", res)
	}
}

func TestParseHelperStatus(t *testing.T) {
	cur, run := ParseHelperStatus("current=20261009T1\nprevious=20260930T1\ncontainer=running\nlisten=*:443\n")
	if cur != "20261009T1" || !run {
		t.Fatalf("cur=%q run=%v", cur, run)
	}
	cur, run = ParseHelperStatus("container=exited\n")
	if cur != "" || run {
		t.Fatalf("cur=%q run=%v", cur, run)
	}
}

// errUnhealthy используется только в driver-файле; держим ссылку для линтера.
var _ = errUnhealthy
