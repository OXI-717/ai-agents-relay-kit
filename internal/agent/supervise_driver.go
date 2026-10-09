package agent

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/OXI-717/ai-agents-relay-kit/internal/xraystats"
)

// XrayHealth — живость xray по его gRPC-API (127.0.0.1:10085):
// GetSysStats отвечает → ядро живо. Зомби-случай CR 9.10 (контейнер
// «running», порт слушает, сервис мёртв) ловится именно здесь.
type XrayHealth struct{ C *xraystats.Client }

func (h XrayHealth) Alive(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	_, err := h.C.SysStats(cctx)
	return err
}

// VpnHelper — обёртка над /usr/local/sbin/vpn-helper (запускается от root).
type VpnHelper struct{ Path string }

func (v VpnHelper) Status() (string, bool, error) {
	out, err := exec.Command(v.Path, "status").CombinedOutput()
	if err != nil {
		return "", false, fmt.Errorf("vpn-helper status: %v: %s", err, out)
	}
	cur, running := ParseHelperStatus(string(out))
	return cur, running, nil
}

func (v VpnHelper) Activate(id string) error {
	if out, err := exec.Command(v.Path, "activate", id).CombinedOutput(); err != nil {
		return fmt.Errorf("vpn-helper activate: %v: %s", err, out)
	}
	return nil
}

// NewSupervisor — связка для vpn-agent -supervise.
func NewSupervisor(apiAddr, helperPath string) (HealthChecker, HelperDriver) {
	return XrayHealth{C: xraystats.New(apiAddr)}, VpnHelper{Path: helperPath}
}

var errUnhealthy = errors.New("unhealthy")
