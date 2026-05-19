package server

import (
	"log/slog"
	"time"

	"golang.org/x/crypto/ssh/agent"
)

type ServerOption func(*Server)

func WithAgent(sshagent agent.Agent) ServerOption {
	return func(s *Server) {
		s.agent = sshagent
	}
}

func WithLogger(logger *slog.Logger) ServerOption {
	return func(s *Server) {
		s.logger = logger
	}
}

func WithTimeout(timeout time.Duration) ServerOption {
	return func(s *Server) {
		s.timeout = timeout
	}
}
