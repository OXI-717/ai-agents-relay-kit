// Package deploy pushes releases to servers and bootstraps new hosts.
package deploy

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"github.com/OXI-717/ai-agents-relay-kit/internal/remote"
)

func Bootstrap(ctx context.Context, run remote.Runner, s registry.Server, helper []byte, deployPubKey string) error {
	out, err := run.Run(ctx, s, true, fmt.Sprintf("ss -ltnpH 'sport = :%d'", s.Port), nil)
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "" && !strings.Contains(string(out), "xray") {
		return fmt.Errorf("%s: %d busy: %s", s.ID, s.Port, strings.TrimSpace(string(out)))
	}
	steps := []struct {
		cmd   string
		stdin []byte
	}{
		{"docker version --format '{{.Server.Version}}'", nil},
		{"id vpn-deploy >/dev/null 2>&1 || useradd --system --create-home --shell /bin/bash vpn-deploy", nil},
		{"install -d -m 700 -o vpn-deploy -g vpn-deploy ~vpn-deploy/.ssh && cat > ~vpn-deploy/.ssh/authorized_keys && chown vpn-deploy: ~vpn-deploy/.ssh/authorized_keys && chmod 600 ~vpn-deploy/.ssh/authorized_keys", []byte(deployPubKey + "\n")},
		{"cat > /usr/local/sbin/vpn-helper && chown root:root /usr/local/sbin/vpn-helper && chmod 755 /usr/local/sbin/vpn-helper", helper},
		{"echo 'vpn-deploy ALL=(root) NOPASSWD: /usr/local/sbin/vpn-helper' > /etc/sudoers.d/vpn-deploy && chmod 440 /etc/sudoers.d/vpn-deploy && visudo -cf /etc/sudoers.d/vpn-deploy", nil},
		{"install -d -m 700 /etc/vpn-xray /etc/vpn-xray/releases", nil},
	}
	for _, st := range steps {
		if _, err := run.Run(ctx, s, true, st.cmd, st.stdin); err != nil {
			return err
		}
	}
	return nil
}

type TargetResult struct {
	Domain    string
	TLS13, H2 bool
	ConnectMS int
}

var probeHostname = regexp.MustCompile(`^[a-z0-9.-]+$`)

// ProbeTarget checks a Reality target from the server itself: TLS 1.3 + ALPN h2 + valid cert.
func ProbeTarget(ctx context.Context, run remote.Runner, s registry.Server, domain string) (TargetResult, error) {
	res := TargetResult{Domain: domain}
	if !probeHostname.MatchString(domain) {
		return res, fmt.Errorf("invalid probe hostname")
	}
	cmd := fmt.Sprintf("curl -s -o /dev/null --http2 --tlsv1.3 --max-time 8 -w '%%{http_version} %%{ssl_verify_result} %%{time_connect}' 'https://%s/'", domain)
	out, err := run.Run(ctx, s, true, cmd, nil)
	if err != nil {
		return res, err
	}
	f := strings.Fields(string(out))
	if len(f) != 3 {
		return res, fmt.Errorf("%s: unexpected curl output %q", domain, out)
	}
	res.H2 = f[0] == "2"
	res.TLS13 = f[1] == "0" // curl --tlsv1.3 fails the handshake otherwise; 0 = cert verified
	sec, _ := strconv.ParseFloat(f[2], 64)
	res.ConnectMS = int(sec * 1000)
	return res, nil
}
