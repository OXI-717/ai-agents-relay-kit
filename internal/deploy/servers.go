package deploy

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"time"

	"github.com/OXI-717/ai-agents-relay-kit/internal/build"
	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"github.com/OXI-717/ai-agents-relay-kit/internal/remote"
)

var releasePattern = regexp.MustCompile(`^[0-9]{8}T[0-9]{15}Z$`)
var imagePattern = regexp.MustCompile(`^ghcr\.io/xtls/xray-core@sha256:[0-9a-f]{64}$`)

// Verifier proves a deployed server works. Server checks every profile,
// including relay pairs; ServerDirect checks only profiles whose entry is the
// server itself, so an exit can be verified before the relays depending on it.
type Verifier interface {
	Server(ctx context.Context, s registry.Server) error
	ServerDirect(ctx context.Context, s registry.Server) error
}

// VerifyFunc adapts a single function to Verifier; it runs for both checks.
type VerifyFunc func(ctx context.Context, s registry.Server) error

func (f VerifyFunc) Server(ctx context.Context, s registry.Server) error { return f(ctx, s) }
func (f VerifyFunc) ServerDirect(ctx context.Context, s registry.Server) error {
	return f(ctx, s)
}

type Mode int

const (
	StopOnError Mode = iota
	Revoke
)

type Result struct {
	Server     string
	Err        error
	RolledBack bool
	Status     string
	Warning    bool
}

const helper = "sudo /usr/local/sbin/vpn-helper "

func one(ctx context.Context, r *registry.Registry, run remote.Runner, verify func(context.Context, registry.Server) error, s registry.Server, id string, mode Mode) Result {
	res := Result{Server: s.ID, Status: "active, verify ok"}
	if !releasePattern.MatchString(id) || !imagePattern.MatchString(r.Pins.ServerImage) {
		res.Err = fmt.Errorf("invalid release id or image")
		return res
	}

	cfg, err := build.ServerConfig(r, s)
	if err != nil {
		res.Err = err
		return res
	}
	h := helper
	if _, err := run.Run(ctx, s, false, h+"install "+id+" "+r.Pins.ServerImage, cfg); err != nil {
		res.Err = err
		return res
	}
	if _, err := run.Run(ctx, s, false, h+"test "+id, nil); err != nil {
		res.Err = fmt.Errorf("%s: xray -test failed, not activated: %w", s.ID, err)
		return res
	}
	if _, err := run.Run(ctx, s, false, h+"activate "+id, nil); err != nil {
		res.Err = err
	} else if verify != nil {
		if err := verify(ctx, s); err != nil {
			res.Err = fmt.Errorf("%s: verify failed: %w", s.ID, err)
		}
	}
	if res.Err == nil && mode == Revoke {
		if _, err := run.Run(ctx, s, false, h+"seal "+id, nil); err != nil {
			res.Err = fmt.Errorf("seal failed: %w", err)
		}
	}
	if res.Err != nil && mode != Revoke {
		if _, rbErr := run.Run(ctx, s, false, h+"rollback", nil); rbErr != nil {
			res.Err = fmt.Errorf("%v; ROLLBACK FAILED: %v", res.Err, rbErr)
		} else {
			res.RolledBack = true
		}
		return res
	}
	if res.Err == nil {
		_, _ = run.Run(ctx, s, false, h+"prune", nil)
	}
	return res
}

// exitAccess reports whether the exit has profiles entered directly and
// profiles entered through a relay. A profile build error means "direct":
// verify then surfaces the same error it always did.
func exitAccess(r *registry.Registry, s registry.Server) (direct, viaRelay bool) {
	for _, u := range r.ActiveUsers() {
		ps, err := build.Profiles(r, u)
		if err != nil {
			return true, false
		}
		for _, p := range ps {
			if p.Server.ID == s.ID {
				direct = true
			} else if s.Kind == "exit" && p.Exit.ID == s.ID {
				viaRelay = true
			}
		}
	}
	return direct, viaRelay
}

// relayQueued reports whether a relay serving the exit is still waiting to be
// deployed in this run.
func relayQueued(queue map[string]bool, r *registry.Registry, e registry.Server) bool {
	for id := range queue {
		q, ok := r.ServerByID(id)
		if !ok {
			continue
		}
		for _, x := range q.Exits {
			if x == e.ID {
				return true
			}
		}
	}
	return false
}

func Servers(ctx context.Context, r *registry.Registry, run remote.Runner, verify Verifier, only string, mode Mode, releaseID string) []Result {
	var out []Result
	ordered := append([]registry.Server(nil), r.Servers...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].Kind == "exit" && ordered[j].Kind != "exit" })
	// Relays this run will still deploy: exits reached through them cannot be
	// fully verified until their relay is activated.
	queue := map[string]bool{}
	for _, s := range ordered {
		if s.Kind == "relay" && s.Enabled && s.SSH.User != "" && (only == "" || s.ID == only) {
			queue[s.ID] = true
		}
	}
	var pending []string           // exits awaiting relay-pair verify, deploy order
	pendingIdx := map[string]int{} // exit id → index in out
	aborted := false
	// revertExit restores an exit whose deferred verify failed or never ran:
	// rollback in deploy mode, fail-closed stop in Revoke.
	revertExit := func(e registry.Server) (bool, error) {
		cmd := "rollback"
		if mode == Revoke {
			cmd = "stop"
		}
		_, err := run.Run(ctx, e, false, helper+cmd, nil)
		return err == nil && mode != Revoke, err
	}
	for _, s := range ordered {
		if only != "" && s.ID != only {
			continue
		}
		var res Result
		switch {
		case s.SSH.User == "":
			res = Result{Server: s.ID, Status: "never deployed"}
		case !s.Enabled:
			_, err := run.Run(ctx, s, false, helper+"stop", nil)
			res = Result{Server: s.ID, Status: "stopped", Err: err, Warning: err != nil && mode != Revoke}
		case s.Kind != "exit" && s.Kind != "relay":
			res = Result{Server: s.ID, Err: fmt.Errorf("unsupported deployed server kind")}
		default:
			var vf func(context.Context, registry.Server) error
			deferred := false
			if verify != nil {
				vf = verify.Server
				if s.Kind == "exit" && relayQueued(queue, r, s) {
					if direct, viaRelay := exitAccess(r, s); viaRelay {
						deferred = true
						vf = verify.ServerDirect
						if !direct {
							vf = nil
						}
					}
				}
			}
			res = one(ctx, r, run, vf, s, releaseID, mode)
			if deferred && res.Err == nil {
				res.Status = "active, exit verify deferred to relay"
				pending = append(pending, s.ID)
				pendingIdx[s.ID] = len(out)
			}
		}
		if s.Kind == "relay" {
			delete(queue, s.ID)
			// A relay is up: verify every exit whose pairs were waiting on
			// relays that are all deployed now. A failure rolls the relay
			// back as usual and names the exit.
			if res.Err == nil && verify != nil {
				for _, exitID := range pending {
					idx, tracked := pendingIdx[exitID]
					if !tracked {
						continue
					}
					e, ok := r.ServerByID(exitID)
					if !ok || relayQueued(queue, r, e) {
						continue
					}
					if err := verify.Server(ctx, e); err != nil {
						reverted, rvErr := revertExit(e)
						out[idx].Status = "active, verify via relay failed"
						out[idx].Err = fmt.Errorf("%s: exit verify via relay failed: %w", e.ID, err)
						out[idx].RolledBack = reverted
						if rvErr != nil {
							out[idx].Err = fmt.Errorf("%v; RECOVERY FAILED: %v", out[idx].Err, rvErr)
						}
						res.Status = "active, exit verify failed"
						res.Err = fmt.Errorf("%s: exit %s verify failed: %w", s.ID, e.ID, err)
						if mode != Revoke {
							if _, rbErr := run.Run(ctx, s, false, helper+"rollback", nil); rbErr != nil {
								res.Err = fmt.Errorf("%v; ROLLBACK FAILED: %v", res.Err, rbErr)
							} else {
								res.RolledBack = true
							}
						}
						break
					}
					out[idx].Status = "active, verify ok"
					delete(pendingIdx, exitID)
				}
			}
		}
		if res.Err != nil && mode == Revoke {
			res.Status = "unconfirmed revocation"
			if _, err := run.Run(ctx, s, false, helper+"stop", nil); err != nil {
				res.Err = fmt.Errorf("unconfirmed revocation: %v; STOP FAILED: %w", res.Err, err)
			} else {
				res.Status = "stopped (fail-closed)"
				res.Err = fmt.Errorf("stopped (fail-closed): %w", res.Err)
			}
		}
		out = append(out, res)
		if res.Err != nil && !res.Warning && mode == StopOnError {
			aborted = true
			break
		}
	}
	// An aborted run leaves deferred exits activated but never verified:
	// they are not confirmed, so restore their previous release too.
	if aborted && verify != nil {
		for _, exitID := range pending {
			idx, tracked := pendingIdx[exitID]
			if !tracked {
				continue
			}
			e, ok := r.ServerByID(exitID)
			if !ok {
				continue
			}
			reverted, rvErr := revertExit(e)
			out[idx].Status = "rolled back, deferred verify did not run"
			out[idx].Err = fmt.Errorf("%s: deploy aborted before deferred verify", e.ID)
			out[idx].RolledBack = reverted
			if rvErr != nil {
				out[idx].Err = fmt.Errorf("%v; ROLLBACK FAILED: %v", out[idx].Err, rvErr)
			}
		}
	}
	// Exits still deferred once the queue is empty (their relay was filtered
	// out or failed in Revoke mode) get a final check so deploy never leaves
	// an exit silently unverified.
	if !aborted && verify != nil {
		for _, exitID := range pending {
			idx, tracked := pendingIdx[exitID]
			if !tracked {
				continue
			}
			e, ok := r.ServerByID(exitID)
			if !ok {
				continue
			}
			if err := verify.Server(ctx, e); err != nil {
				reverted, rvErr := revertExit(e)
				out[idx].Err = fmt.Errorf("%s: exit verify via relay failed: %w", e.ID, err)
				out[idx].RolledBack = reverted
				if mode == Revoke && rvErr == nil {
					out[idx].Status = "stopped (fail-closed)"
				} else {
					out[idx].Status = "active, verify via relay failed"
				}
				if rvErr != nil {
					out[idx].Err = fmt.Errorf("%v; RECOVERY FAILED: %v", out[idx].Err, rvErr)
				}
				out = append(out, Result{Server: exitID, Status: "verify via relay failed",
					Err: fmt.Errorf("%s: exit verify via relay failed: %w", exitID, err)})
			} else {
				out[idx].Status = "active, verify ok"
			}
		}
	}
	return out
}

// ReleaseID uses fixed-width UTC nanoseconds so chronological and lexical order agree.
func ReleaseID(now time.Time) string {
	now = now.UTC()
	return fmt.Sprintf("%s%09dZ", now.Format("20060102T150405"), now.Nanosecond())
}
