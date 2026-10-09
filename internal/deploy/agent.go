package deploy

import (
	"context"
	"fmt"

	"github.com/OXI-717/ai-agents-relay-kit/internal/registry"
	"github.com/OXI-717/ai-agents-relay-kit/internal/remote"
)

// BootstrapAgent installs vpn-agent on a freshly bootstrapped host: an
// unprivileged user that can reach only the loopback stats API, the binary,
// the HMAC key (0600) and a systemd timer running every 5 minutes.
// Runs as root alongside Bootstrap.
func BootstrapAgent(ctx context.Context, run remote.Runner, s registry.Server, agentBin, agentConf, hmacKey, serviceUnit, timerUnit, supervisorService, supervisorTimer []byte) error {
	steps := []struct {
		cmd   string
		stdin []byte
	}{
		{"id vpn-agent >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin vpn-agent", nil},
		{"install -d -m 700 -o vpn-agent -g vpn-agent /var/lib/vpn-agent && install -d -m 750 -o root -g vpn-agent /etc/vpn-agent", nil},
		{"cat > /usr/local/bin/vpn-agent && chown root:root /usr/local/bin/vpn-agent && chmod 755 /usr/local/bin/vpn-agent", agentBin},
		{"cat > /etc/vpn-agent/hmac.key && chown root:vpn-agent /etc/vpn-agent/hmac.key && chmod 640 /etc/vpn-agent/hmac.key", hmacKey},
		{"cat > /etc/vpn-agent/agent.json && chown root:vpn-agent /etc/vpn-agent/agent.json && chmod 640 /etc/vpn-agent/agent.json", agentConf},
		{"cat > /etc/systemd/system/vpn-agent.service && chmod 644 /etc/systemd/system/vpn-agent.service", serviceUnit},
		{"cat > /etc/systemd/system/vpn-agent.timer && chmod 644 /etc/systemd/system/vpn-agent.timer", timerUnit},
		{"cat > /etc/systemd/system/vpn-supervisor.service && chmod 644 /etc/systemd/system/vpn-supervisor.service", supervisorService},
		{"cat > /etc/systemd/system/vpn-supervisor.timer && chmod 644 /etc/systemd/system/vpn-supervisor.timer", supervisorTimer},
		{"systemctl daemon-reload && systemctl enable --now vpn-agent.timer vpn-supervisor.timer", nil},
	}
	for _, st := range steps {
		if _, err := run.Run(ctx, s, true, st.cmd, st.stdin); err != nil {
			return err
		}
	}
	return nil
}

// AgentConfig is the /etc/vpn-agent/agent.json payload (no secrets inside).
func AgentConfig(s registry.Server, subBaseURL string) []byte {
	return fmt.Appendf(nil, `{"server":%q,"api_addr":"127.0.0.1:%d","ingest_url":%q,"key_file":"/etc/vpn-agent/hmac.key","state_dir":"/var/lib/vpn-agent"}`+"\n",
		s.ID, registry.XrayAPIPort, subBaseURL+"/ingest")
}
