package tunneller

import (
	"time"

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
