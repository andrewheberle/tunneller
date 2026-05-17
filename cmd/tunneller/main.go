package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/andrewheberle/tunneller/internal/pkg/regexpflag"
	"github.com/andrewheberle/tunneller/internal/pkg/tunneller"
	"github.com/spf13/pflag"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	var (
		addr           string
		keys           []string
		sshhost        string
		sshport        string
		sshuser        string
		endpointport   string
		endpointscheme string
		sshtimeout     time.Duration
	)

	allowJumphost := regexpflag.MustCompile(".*")
	allowJumphostUser := regexpflag.MustCompile("^jump$")
	allowJumphostPort := regexpflag.MustCompile("^22$")
	allowEndpoint := regexpflag.MustCompile(".*")
	allowEndpointScheme := regexpflag.MustCompile("^http(s)?$")
	allowEndpointPort := regexpflag.MustCompile("^(80|443)$")

	pflag.StringVar(&addr, "addr", ":8080", "Listen address")
	pflag.StringSliceVar(&keys, "key", []string{}, "SSH key(s) to load for authentication")
	pflag.StringVar(&sshhost, "ssh", "", "Default SSH jump host")
	pflag.Var(allowJumphost, "ssh.allow", "Allowed SSH jump hosts (regexp)")
	pflag.StringVar(&sshuser, "ssh.user", "jump", "Default SSH user to use for jump host")
	pflag.DurationVar(&sshtimeout, "ssh.timeout", time.Minute*5, "Idle timeout for SSH jump host connections")
	pflag.Var(allowJumphostUser, "ssh.user.allow", "Allowed SSH user for jump host (regexp)")
	pflag.Var(allowJumphostPort, "ssh.port.allow", "Allowed SSH port for jump host (regexp)")
	pflag.StringVar(&sshport, "ssh.port", "22", "SSH port for jump host")
	pflag.Var(allowEndpoint, "endpoint.allow", "Allowed remote endpoints (regexp)")
	pflag.StringVar(&endpointport, "endpoint.port", "80", "Default endpoint port")
	pflag.Var(allowEndpointPort, "endpoint.port.allow", "Allowed remote endpoint ports (regexp)")
	pflag.StringVar(&endpointscheme, "endpoint.scheme", "http", "Default endpoint scheme")
	pflag.Var(allowEndpointScheme, "endpoint.scheme.allow", "Allowed remote endpoint schemes (regexp)")

	pflag.Parse()

	srv := &server{
		tunnels:               make(map[string]*tunneller.Tunnel),
		allowedjumphost:       allowJumphost.Regexp(),
		allowedjumphostuser:   allowJumphostUser.Regexp(),
		allowedjumphostport:   allowJumphostPort.Regexp(),
		sshhost:               sshhost,
		sshport:               sshport,
		sshuser:               sshuser,
		sshtimeout:            sshtimeout,
		allowedendpoint:       allowEndpoint.Regexp(),
		allowedendpointport:   allowEndpointPort.Regexp(),
		allowedendpointscheme: allowEndpointScheme.Regexp(),
		endpointport:          endpointport,
		endpointscheme:        endpointscheme,
	}

	// load any ssh keys
	if len(keys) > 0 {
		a := agent.NewKeyring()
		for _, keyfile := range keys {
			b, err := os.ReadFile(keyfile)
			if err != nil {
				slog.Error("could not read private key", "key", keyfile, "error", err)
				continue
			}

			priv, err := ssh.ParseRawPrivateKey(b)
			if err != nil {
				slog.Error("could not parse private key", "key", keyfile, "error", err)
				continue
			}

			if err := a.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
				slog.Error("could not add key to agent", "key", keyfile, "error", err)
				continue
			}
		}

		l, err := a.List()
		if err != nil {
			slog.Error("could not list agent keys", "error", err)
		} else {
			// set up agent if any keys were added
			if len(l) > 0 {
				srv.agent = a
			}
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/{jumphostuser}/{jumphost}/{jumphostport}/{scheme}/{endpoint}/{port}/", srv)
	mux.Handle("/{jumphostuser}/{jumphost}/{scheme}/{endpoint}/{port}/", srv)
	mux.Handle("/{jumphost}/{scheme}/{endpoint}/{port}/", srv)
	mux.Handle("/{jumphost}/{scheme}/{endpoint}/", srv)
	mux.Handle("/{jumphost}/{endpoint}/", srv)
	mux.Handle("/{endpoint}/", srv)

	slog.Info("starting tunnel-proxy", "addr", addr)
	if err := http.ListenAndServe(addr, mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server exited", "err", err)
		os.Exit(1)
	}
}

// server holds the active tunnel registry.
type server struct {
	mu             sync.Mutex
	tunnels        map[string]*tunneller.Tunnel
	agent          agent.Agent
	sshhost        string
	sshport        string
	sshuser        string
	sshtimeout     time.Duration
	endpointport   string
	endpointscheme string

	allowedjumphost       *regexp.Regexp
	allowedjumphostport   *regexp.Regexp
	allowedjumphostuser   *regexp.Regexp
	allowedendpoint       *regexp.Regexp
	allowedendpointport   *regexp.Regexp
	allowedendpointscheme *regexp.Regexp
}

// ServeHTTP handles all /{siteid}/{customerid}/... requests.
func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	jumphost := r.PathValue("jumphost")
	if jumphost == "" {
		jumphost = s.sshhost
	}
	if jumphost == "" {
		http.Error(w, "Bad Request - No Jumphost Available", http.StatusBadRequest)
		return
	}
	if !s.allowedjumphost.Match([]byte(jumphost)) {
		http.Error(w, "Forbidden - Bad Jumphost", http.StatusForbidden)
		return
	}

	jumphostuser := r.PathValue("jumphostuser")
	if jumphostuser == "" {
		jumphostuser = s.sshuser
	}
	if !s.allowedjumphostuser.Match([]byte(jumphostuser)) {
		http.Error(w, "Forbidden - Bad Jumphost User", http.StatusForbidden)
		return
	}

	jumphostport := r.PathValue("jumphostport")
	if jumphostport == "" {
		jumphostport = s.sshport
	}
	if !s.allowedjumphostport.Match([]byte(jumphostport)) {
		http.Error(w, "Forbidden - Bad Jumphost Port", http.StatusForbidden)
		return
	}

	scheme := r.PathValue("scheme")
	if scheme == "" {
		scheme = s.endpointscheme
	}
	if !s.allowedendpointscheme.Match([]byte(scheme)) {
		http.Error(w, "Forbidden - Bad Scheme", http.StatusForbidden)
		return
	}

	port := r.PathValue("port")
	if port == "" {
		port = s.endpointport
	}
	if !s.allowedendpointport.Match([]byte(port)) {
		http.Error(w, "Forbidden - Bad Port", http.StatusForbidden)
		return
	}

	endpoint := r.PathValue("endpoint")
	if jumphost == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if !s.allowedendpoint.Match([]byte(endpoint)) {
		http.Error(w, "Forbidden - Bad Endpoint", http.StatusForbidden)
		return
	}

	logger := slog.With(
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
func (s *server) getOrCreateTunnel(logger *slog.Logger, user, jumphost, scheme, endpoint, port string) (*tunneller.Tunnel, error) {
	key := fmt.Sprintf("%s@%s/%s://%s:%s", user, jumphost, scheme, endpoint, port)

	s.mu.Lock()
	defer s.mu.Unlock()

	if t, ok := s.tunnels[key]; ok {
		return t, nil
	}

	ep := tunneller.SSHEndpoint{
		Host:           fmt.Sprintf("%s:%s", jumphost, s.sshport),
		User:           user,
		EndpointScheme: scheme,
		EndpointAddr:   fmt.Sprintf("%s:%s", endpoint, port),
	}

	// add timeout and ssh agent if we loaded keys
	opts := []tunneller.TunnelOption{tunneller.WithIdleTimeout(s.sshtimeout)}
	if s.agent != nil {
		opts = append(opts, tunneller.WithAgent(s.agent))
	}

	t, err := tunneller.NewTunnel(ep, func() {
		s.mu.Lock()
		delete(s.tunnels, key)
		s.mu.Unlock()
		logger.Info("tunnel torn down (idle timeout)", "jumphost", jumphost, "endpoint", endpoint, "port", port)
	}, opts...)
	if err != nil {
		return nil, fmt.Errorf("create tunnel: %w", err)
	}

	logger.Info("tunnel established", "jumphost", jumphost, "endpoint", endpoint, "port", port)
	s.tunnels[key] = t
	return t, nil
}
