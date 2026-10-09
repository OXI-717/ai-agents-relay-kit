// Package xraystats is a minimal gRPC-over-h2c client for the xray StatsService
// on 127.0.0.1 — small enough for the static vpn-agent binary, no protobuf dep.
package xraystats

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/net/http2"
)

const service = "/xray.app.stats.command.StatsService"

// Invoker sends one framed gRPC request and returns the framed reply.
// The real implementation is HTTP/2 over loopback; tests substitute a fake.
type Invoker func(ctx context.Context, method string, req []byte) ([]byte, error)

type Client struct {
	Invoke Invoker
}

// New returns a client for the xray API listening on addr (e.g. 127.0.0.1:10085).
func New(addr string) *Client {
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLSContext: func(ctx context.Context, network, a string, _ *tls.Config) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", addr)
		},
	}
	hc := &http.Client{Transport: tr}
	return &Client{Invoke: func(ctx context.Context, method string, reqBody []byte) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "POST", "http://xray"+service+"/"+method, bytes.NewReader(reqBody))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/grpc")
		req.Header.Set("TE", "trailers")
		resp, err := hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("stats %s: %w", method, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("stats %s: %s", method, resp.Status)
		}
		msg, err := unframe(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("stats %s: %w", method, err)
		}
		if st := resp.Trailer.Get("grpc-status"); st != "" && st != "0" {
			return nil, fmt.Errorf("stats %s: grpc-status %s: %s", method, st, resp.Trailer.Get("grpc-message"))
		}
		return msg, nil
	}}
}

// QueryStats returns absolute values for stats whose names contain pattern.
func (c *Client) QueryStats(ctx context.Context, pattern string) (map[string]int64, error) {
	msg, err := c.Invoke(ctx, "QueryStats", encQueryStats(pattern, false))
	if err != nil {
		return nil, err
	}
	return decQueryStats(msg)
}

func (c *Client) SysStats(ctx context.Context) (SysStats, error) {
	msg, err := c.Invoke(ctx, "GetSysStats", frame(nil))
	if err != nil {
		return SysStats{}, err
	}
	return decSysStats(msg)
}

// OnlineIPs returns the total number of distinct client IPs currently online.
func (c *Client) OnlineIPs(ctx context.Context) (int, error) {
	msg, err := c.Invoke(ctx, "GetStatsOnlineIpList", frame(nil))
	if err != nil {
		return 0, err
	}
	return decOnlineIPs(msg)
}
