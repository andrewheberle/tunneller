package server

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
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

// ServeHTTP handles all /{siteid}/{customerid}/... requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jumphost := r.PathValue("jumphost")
	if jumphost == "" {
		jumphost = s.SSHHost
	}
	if jumphost == "" {
		http.Error(w, "Bad Request - No Jumphost Available", http.StatusBadRequest)
		return
	}
	if !s.AllowedJumphost.Match([]byte(jumphost)) {
		http.Error(w, "Forbidden - Bad Jumphost", http.StatusForbidden)
		return
	}

	jumphostuser := r.PathValue("jumphostuser")
	if jumphostuser == "" {
		jumphostuser = s.SSHUser
	}
	if !s.AllowedJumphostUser.Match([]byte(jumphostuser)) {
		http.Error(w, "Forbidden - Bad Jumphost User", http.StatusForbidden)
		return
	}

	jumphostport := r.PathValue("jumphostport")
	if jumphostport == "" {
		jumphostport = s.SSHPort
	}
	if !s.AllowedJumphostPort.Match([]byte(jumphostport)) {
		http.Error(w, "Forbidden - Bad Jumphost Port", http.StatusForbidden)
		return
	}

	scheme := r.PathValue("scheme")
	if scheme == "" {
		scheme = s.EndpointScheme
	}
	if !s.AllowedEndpointScheme.Match([]byte(scheme)) {
		http.Error(w, "Forbidden - Bad Scheme", http.StatusForbidden)
		return
	}

	port := r.PathValue("port")
	if port == "" {
		port = s.EndpointPort
	}
	if !s.AllowedEndpointPort.Match([]byte(port)) {
		http.Error(w, "Forbidden - Bad Port", http.StatusForbidden)
		return
	}

	endpoint := r.PathValue("endpoint")
	if jumphost == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !s.AllowedEndpoint.Match([]byte(endpoint)) {
		http.Error(w, "Forbidden - Bad Endpoint", http.StatusForbidden)
		return
	}

	logger := s.Logger.With(
		slog.Group("jumphost", "user", jumphostuser, "address", jumphost),
		slog.Group("endpoint", "address", endpoint, "port", port),
	)

	t, err := s.getOrCreateTunnel(logger, jumphostuser, jumphost, scheme, endpoint, port)
	if err != nil {
		logger.Error("tunnel unavailable", "error", err)
		http.Error(w, "tunnel unavailable", http.StatusBadGateway)
		return
	}

	t.ProxyHandler(strings.TrimSuffix(r.URL.Path, "/")).ServeHTTP(w, r)
}

// getOrCreateTunnel returns an existing tunnel for the key or establishes a
// new one. Separate tunnels per request path.
func (s *Server) getOrCreateTunnel(logger *slog.Logger, user, jumphost, scheme, endpoint, port string) (*tunneller.Tunnel, error) {
	key := tunnelKey(user, jumphost, scheme, endpoint, port)

	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.Tunnels[key]; ok {
		logger.Debug("reusing existing tunnel", "key", key)
		return t, nil
	}

	ep := tunneller.SSHEndpoint{
		Host:           fmt.Sprintf("%s:%s", jumphost, s.SSHPort),
		User:           user,
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
	return fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "%s@%s/%s://%s:%s", a...)))
}
