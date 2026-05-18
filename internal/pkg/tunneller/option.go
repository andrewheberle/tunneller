package tunneller

import (
	"crypto/tls"
	"time"

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
