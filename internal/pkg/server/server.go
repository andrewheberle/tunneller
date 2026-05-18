package server

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/andrewheberle/tunneller/internal/pkg/tunneller"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// server holds the active tunnel registry.
type Server struct {
	mu              sync.Mutex
	Tunnels         map[string]*tunneller.Tunnel
	Agent           agent.Agent
	SSHHost         string
	SSHPort         string
	SSHUser         string
	SSHTimeout      time.Duration
	EndpointPort    string
	EndpointScheme  string
	ProxyTlsConfig  *tls.Config
	HostKeyCallback ssh.HostKeyCallback
	Logger          *slog.Logger

	AllowedJumphost       *regexp.Regexp
	AllowedJumphostPort   *regexp.Regexp
	AllowedJumphostUser   *regexp.Regexp
	AllowedEndpoint       *regexp.Regexp
	AllowedEndpointPort   *regexp.Regexp
	AllowedEndpointScheme *regexp.Regexp
}

// ServeHTTP handles all requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	scheme := r.PathValue("scheme")
	if scheme == "" {
		http.Error(w, "Bad Request - No Endpoint Scheme", http.StatusBadRequest)
		return
	}
	if !s.AllowedEndpointScheme.Match([]byte(scheme)) {
		http.Error(w, "Forbidden - Bad Scheme", http.StatusForbidden)
		return
	}

	endpoint := r.PathValue("endpoint")
	if endpoint == "" {
		http.Error(w, "Bad Request - No Endpoint", http.StatusBadRequest)
		return
	}
	if !s.AllowedEndpoint.Match([]byte(endpoint)) {
		http.Error(w, "Forbidden - Bad Endpoint", http.StatusForbidden)
		return
	}

	port := r.PathValue("port")
	if port == "" {
		http.Error(w, "Bad Request - No Endpoint Port", http.StatusBadRequest)
		return
	}
	if !s.AllowedEndpointPort.Match([]byte(port)) {
		http.Error(w, "Forbidden - Bad Port", http.StatusForbidden)
		return
	}

	logger := s.Logger.With(
		slog.Group("jumphost", "user", s.SSHUser, "address", s.SSHHost, "port", s.SSHPort),
		slog.Group("endpoint", "scheme", scheme, "address", endpoint, "port", port),
	)

	t, err := s.getOrCreateTunnel(logger, scheme, endpoint, port)
	if err != nil {
		logger.Error("tunnel unavailable", "error", err)
		http.Error(w, "tunnel unavailable", http.StatusBadGateway)
		return
	}

	t.ProxyHandler(fmt.Sprintf("/%s/%s/%s", scheme, endpoint, port)).ServeHTTP(w, r)
}

// getOrCreateTunnel returns an existing tunnel for the key or establishes a
// new one. Separate tunnels per request path.
func (s *Server) getOrCreateTunnel(logger *slog.Logger, scheme, endpoint, port string) (*tunneller.Tunnel, error) {
	key := tunnelKey(scheme, endpoint, port)

	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.Tunnels[key]; ok {
		logger.Debug("reusing existing tunnel", "key", key)
		return t, nil
	}

	ep := tunneller.SSHEndpoint{
		Host:           fmt.Sprintf("%s:%s", s.SSHHost, s.SSHPort),
		User:           s.SSHUser,
		EndpointScheme: scheme,
		EndpointAddr:   fmt.Sprintf("%s:%s", endpoint, port),
	}

	// add timeout and ssh agent if we loaded keys
	opts := []tunneller.TunnelOption{tunneller.WithIdleTimeout(s.SSHTimeout)}
	if s.Agent != nil {
		opts = append(opts, tunneller.WithAgent(s.Agent))
	}
	if s.HostKeyCallback != nil {
		opts = append(opts, tunneller.WithHostKeyCallback(s.HostKeyCallback))
	}
	if s.ProxyTlsConfig != nil {
		opts = append(opts, tunneller.WithTlsConfig(s.ProxyTlsConfig))
	}

	t, err := tunneller.NewTunnel(ep, func() {
		s.mu.Lock()
		delete(s.Tunnels, key)
		s.mu.Unlock()
		logger.Info("tunnel torn down (idle timeout)", "key", key)
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("create tunnel: %w", err)
	}

	logger.Info("tunnel established", "key", key)
	s.Tunnels[key] = t
	return t, nil
}

func tunnelKey(a ...any) string {
	return fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "%s://%s:%s", a...)))
}
