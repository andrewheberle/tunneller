package tunneller

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"sync"
	"time"

	"github.com/andrewheberle/tunneller/internal/pkg/tracker"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// tunnel represents an active SSH connection to a remote site, with an idle
// timeout that triggers teardown when no requests have been proxied recently.
type Tunnel struct {
	key             string
	client          *ssh.Client
	endpointScheme  string
	endpointAddr    string
	idleTimeout     time.Duration
	hostKeyCallback ssh.HostKeyCallback
	tlsConfig       *tls.Config
	tracker         *tracker.CookieTracker
	logger          *slog.Logger

	mu            sync.Mutex
	lastUsed      time.Time
	stopTimer     *time.Timer
	onTeardown    func() // called by the tunnel when it tears itself down
	agent         agent.Agent
	defaultScheme string

	rewriteContentRules []*RewriteContentRule
}

// NewTunnel establishes an SSH connection using the provided endpoint and
// returns a ready-to-use tunnel. onTeardown is called when the idle timer
// fires so the caller can remove the tunnel from any registry.
func NewTunnel(ep SSHEndpoint, onTeardown func(), opts ...TunnelOption) (*Tunnel, error) {
	t := &Tunnel{
		endpointScheme:  ep.EndpointScheme,
		endpointAddr:    ep.EndpointAddr,
		lastUsed:        time.Now(),
		onTeardown:      onTeardown,
		idleTimeout:     time.Minute * 5,
		hostKeyCallback: nil,
		tlsConfig:       &tls.Config{InsecureSkipVerify: true},
		logger:          slog.New(slog.DiscardHandler),

		// default of match for form action attributes with single or double quoted absolute paths
		rewriteContentRules: []*RewriteContentRule{
			{
				re: regexp.MustCompile(`action=["'](\/[^"']*)["']`),
				transform: func(prefix string, captured []byte) []byte {
					return append([]byte(prefix), captured...)
				},
			},
		},
	}

	for _, o := range opts {
		o(t)
	}

	// check regexp's
	for _, rewrite := range t.rewriteContentRules {
		if rewrite.re.NumSubexp() != 1 {
			return nil, fmt.Errorf("tunnel: rewrite regexp %q must have exactly one capture group", rewrite.re.String())
		}
	}

	if t.hostKeyCallback == nil {
		return nil, fmt.Errorf("tunnel: host key callback is required")
	}

	authMethods := make([]ssh.AuthMethod, 0)
	if t.agent != nil {
		// add the ssh agent if set
		authMethods = append(authMethods, ssh.PublicKeysCallback(t.agent.Signers))
	}

	cfg := &ssh.ClientConfig{
		User:            ep.User,
		Auth:            authMethods,
		HostKeyCallback: t.hostKeyCallback,
	}

	client, err := ssh.Dial("tcp", ep.Host, cfg)
	if err != nil {
		return nil, fmt.Errorf("tunnel: ssh dial %s: %w", ep.Host, err)
	}
	t.client = client
	t.stopTimer = time.AfterFunc(t.idleTimeout, t.teardown)

	return t, nil
}

// transport returns an http.RoundTripper that dials the endpoint over the SSH
// channel
func (t *Tunnel) transport() http.RoundTripper {
	return &http.Transport{
		DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
			return t.dial()
		},
		TLSClientConfig: t.tlsConfig,
	}
}

// dial opens a new forwarded connection to the endpoint through the SSH tunnel
// and resets the idle timer.
func (t *Tunnel) dial() (net.Conn, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	conn, err := t.client.Dial("tcp", t.endpointAddr)
	if err != nil {
		return nil, fmt.Errorf("tunnel: dial endpoint %s: %w", t.endpointAddr, err)
	}

	t.lastUsed = time.Now()
	t.stopTimer.Reset(t.idleTimeout)

	return conn, nil
}

// teardown closes the SSH connection and notifies the registry.
func (t *Tunnel) teardown() {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.client.Close()
	if t.onTeardown != nil {
		t.onTeardown()
	}
}
