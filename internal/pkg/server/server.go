package server

import (
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/andrewheberle/tunneller/internal/pkg/tracker"
	"github.com/andrewheberle/tunneller/internal/pkg/tunneller"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	DefaultSSHTimeout = time.Minute * 5
	DefaultSSHUser    = "jump"
	DefaultSSHPort    = "22"
)

// server holds the active tunnel registry.
type Server struct {
	mu          sync.Mutex
	tunnels     map[string]*tunneller.Tunnel
	agent       agent.Agent
	logger      *slog.Logger
	tracker     *tracker.CookieTracker
	metricsPath string

	host    string
	port    string
	user    string
	timeout time.Duration

	ProxyTlsConfig  *tls.Config
	HostKeyCallback ssh.HostKeyCallback

	AllowedEndpoint        *regexp.Regexp
	AllowedEndpointPort    *regexp.Regexp
	AllowedEndpointHeaders []string
	AllowedEndpointScheme  *regexp.Regexp

	// metrics
	reg                    *prometheus.Registry
	tunnelCount            prometheus.Gauge
	tunnelEstablishedTotal prometheus.Counter
	tunnelErrorTotal       prometheus.Counter
	tunnelTotal            prometheus.Counter
}

func New(user, host, port string, opts ...ServerOption) (*Server, error) {
	s := &Server{
		user:                   user,
		host:                   host,
		port:                   port,
		tracker:                tracker.NewCookieTracker(),
		tunnels:                make(map[string]*tunneller.Tunnel),
		logger:                 slog.New(slog.DiscardHandler),
		AllowedEndpointHeaders: DefaultEndpointHeadersAllow(),
		reg:                    prometheus.NewRegistry(),
	}

	for _, o := range opts {
		o(s)
	}

	s.tunnelCount = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "tunneller_tunnel_count",
			Help: "Number of active SSH tunnels",
		},
	)
	s.reg.MustRegister(s.tunnelCount)

	s.tunnelEstablishedTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "tunneller_tunnel_established_total",
			Help: "Total number of SSH tunnels established successfully",
		},
	)
	s.reg.MustRegister(s.tunnelEstablishedTotal)

	s.tunnelErrorTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "tunneller_tunnel_error_total",
			Help: "Total number of errors when establishing SSH tunnels",
		},
	)
	s.reg.MustRegister(s.tunnelErrorTotal)

	s.tunnelTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "tunneller_tunnel_total",
			Help: "Total number of SSH tunnels attempted to be established",
		},
	)
	s.reg.MustRegister(s.tunnelTotal)

	s.reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return s, nil
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

	logger := s.logger.With(
		slog.Group("jumphost", "user", s.user, "address", s.host, "port", s.port),
		slog.Group("endpoint", "scheme", scheme, "address", endpoint, "port", port),
	)

	t, err := s.getOrCreateTunnel(logger, scheme, endpoint, port)
	if err != nil {
		s.tunnelErrorTotal.Inc()
		logger.Error("tunnel unavailable", "error", err)
		http.Error(w, "tunnel unavailable", http.StatusBadGateway)
		return
	}

	t.ProxyHandler(fmt.Sprintf("/%s/%s/%s", scheme, endpoint, port), s.AllowedEndpointHeaders).ServeHTTP(w, r)
}

func (s *Server) MetricsHandler() http.Handler {
	return promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{})
}

// getOrCreateTunnel returns an existing tunnel for the key or establishes a
// new one. Separate tunnels per request path.
func (s *Server) getOrCreateTunnel(logger *slog.Logger, scheme, endpoint, port string) (*tunneller.Tunnel, error) {
	key := tunnelKey(scheme, endpoint, port)

	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.tunnels[key]; ok {
		logger.Debug("reusing existing tunnel", "key", key)
		return t, nil
	}

	s.tunnelTotal.Inc()

	ep := tunneller.SSHEndpoint{
		Host:           net.JoinHostPort(s.host, s.port),
		User:           s.user,
		EndpointScheme: scheme,
		EndpointAddr:   net.JoinHostPort(endpoint, port),
	}

	// add timeout and ssh agent if we loaded keys
	opts := []tunneller.TunnelOption{
		tunneller.WithIdleTimeout(s.timeout),
		tunneller.WithKey(key),
		tunneller.WithLogger(logger),
	}
	if s.agent != nil {
		opts = append(opts, tunneller.WithAgent(s.agent))
	}
	if s.HostKeyCallback != nil {
		opts = append(opts, tunneller.WithHostKeyCallback(s.HostKeyCallback))
	}
	if s.ProxyTlsConfig != nil {
		opts = append(opts, tunneller.WithTlsConfig(s.ProxyTlsConfig))
	}
	if s.tracker != nil {
		opts = append(opts, tunneller.WithCookieTracker(s.tracker))
	}

	t, err := tunneller.NewTunnel(ep, func() {
		s.mu.Lock()
		delete(s.tunnels, key)
		s.mu.Unlock()
		s.tunnelCount.Dec()
		logger.Info("tunnel torn down (idle timeout)", "key", key)
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("create tunnel: %w", err)
	}

	s.tunnelEstablishedTotal.Inc()
	s.tunnelCount.Inc()
	logger.Info("tunnel established", "key", key)
	s.tunnels[key] = t
	return t, nil
}

func tunnelKey(a ...any) string {
	return fmt.Sprintf("%x", sha256.Sum256(fmt.Appendf(nil, "%s://%s:%s", a...)))
}

func DefaultEndpointHeadersAllow() []string {
	return []string{
		"Accept",
		"Accept-Encoding",
		"Accept-Language",
		"Authorization",
		"Cache-Control",
		"Connection",
		"Content-Length",
		"Content-Type",
		"Cookie",
		"Origin",
		"Upgrade-Insecure-Requests",
		"User-Agent",
		"Referer",
	}
}
