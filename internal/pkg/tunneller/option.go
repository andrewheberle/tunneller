package tunneller

import (
	"crypto/tls"
	"log/slog"
	"time"

	"github.com/andrewheberle/tunneller/internal/pkg/tracker"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type TunnelOption func(*Tunnel)

func WithAgent(agent agent.Agent) TunnelOption {
	return func(t *Tunnel) {
		t.agent = agent
	}
}

func WithIdleTimeout(timeout time.Duration) TunnelOption {
	return func(t *Tunnel) {
		t.idleTimeout = timeout
	}
}

func WithHostKeyCallback(cb ssh.HostKeyCallback) TunnelOption {
	return func(t *Tunnel) {
		t.hostKeyCallback = cb
	}
}

func WithTlsConfig(config *tls.Config) TunnelOption {
	return func(t *Tunnel) {
		t.tlsConfig = config
	}
}

func WithCookieTracker(tracker *tracker.CookieTracker) TunnelOption {
	return func(t *Tunnel) {
		t.tracker = tracker
	}
}

func WithKey(key string) TunnelOption {
	return func(t *Tunnel) {
		t.key = key
	}
}

func WithLogger(logger *slog.Logger) TunnelOption {
	return func(t *Tunnel) {
		t.logger = logger
	}
}

func WithRewriteContentRule(rewrite ...*RewriteContentRule) TunnelOption {
	return func(t *Tunnel) {
		t.rewriteContentRules = append(t.rewriteContentRules, rewrite...)
	}
}
