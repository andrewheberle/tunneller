package cmd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/andrewheberle/simplecommand"
	"github.com/andrewheberle/simplecommand/vipercommand"
	"github.com/andrewheberle/tunneller/internal/pkg/regexpflag"
	"github.com/andrewheberle/tunneller/internal/pkg/server"
	"github.com/andrewheberle/tunneller/internal/pkg/tunneller"
	"github.com/bep/simplecobra"
	sloghttp "github.com/samber/slog-http"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

type rootCommand struct {
	addr                 string
	keys                 []string
	sshhost              string
	sshport              string
	sshuser              string
	sshknownhosts        string
	sshtimeout           time.Duration
	endpointca           string
	allowEndpoint        *regexpflag.Flag
	allowEndpointPort    *regexpflag.Flag
	allowEndpointScheme  *regexpflag.Flag
	allowEndpointHeaders []string
	metricsenabled       bool
	metricspath          string
	rewrites             []string
	prefix               string
	debug                bool

	mux    http.Handler
	logger *slog.Logger

	*vipercommand.Command
}

var logLevel = new(slog.LevelVar)

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	c.allowEndpoint = regexpflag.MustCompile(".*")
	c.allowEndpointScheme = regexpflag.MustCompile("^http(s)?$")
	c.allowEndpointPort = regexpflag.MustCompile("^(80|443)$")

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.debug, "debug", false, "Enable debug logging")
	cmd.Flags().StringVar(&c.addr, "addr", ":8080", "Listen address")
	cmd.Flags().StringVar(&c.sshhost, "ssh", "", "SSH jump host address")
	cmd.Flags().StringSliceVar(&c.keys, "ssh.key", []string{}, "SSH key(s) to load for jump host authentication")
	cmd.Flags().StringVar(&c.sshknownhosts, "ssh.knownhosts", "", "SSH known_hosts file to verify jump host identity")
	cmd.Flags().StringVar(&c.sshuser, "ssh.user", server.DefaultSSHUser, "SSH user to use for jump host")
	cmd.Flags().StringVar(&c.metricspath, "metrics.path", "/metrics", "Path for Prometheus metrics")
	cmd.Flags().BoolVar(&c.metricsenabled, "metrics.enabled", true, "Enable Prometheus metrics")
	cmd.Flags().DurationVar(&c.sshtimeout, "ssh.timeout", server.DefaultSSHTimeout, "Idle timeout for SSH jump host connections")
	cmd.Flags().StringVar(&c.sshport, "ssh.port", server.DefaultSSHPort, "SSH port for jump host")
	cmd.Flags().Var(c.allowEndpoint, "endpoint.allow", "Allowed remote endpoints (regexp)")
	cmd.Flags().StringVar(&c.endpointca, "endpoint.ca", "", "CA bundle to verify HTTPS connections to endpoints")
	cmd.Flags().Var(c.allowEndpointPort, "endpoint.port.allow", "Allowed remote endpoint ports (regexp)")
	cmd.Flags().Var(c.allowEndpointScheme, "endpoint.scheme.allow", "Allowed remote endpoint schemes (regexp)")
	cmd.Flags().StringSliceVar(&c.allowEndpointHeaders, "endpoint.headers.allow", server.DefaultEndpointHeadersAllow(), "Allowed HTTP headers to pass to endpoint (canonical form)")
	cmd.Flags().StringArrayVar(&c.rewrites, "endpoint.html.rewrite", []string{}, "Rewrites to perform on \"text/html\" responses")
	cmd.Flags().StringVar(&c.prefix, "prefix", "", "Prefix for HTTP proxy endpoint")
	cmd.MarkFlagFilename("ssh")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	if c.debug {
		logLevel.Set(slog.LevelDebug)
	}

	// Always ensure Host header is allowed
	if !slices.Contains(c.allowEndpointHeaders, "Host") {
		c.allowEndpointHeaders = append(c.allowEndpointHeaders, "Host")
	}

	// pass our logger, and timeout
	opts := []server.ServerOption{
		server.WithTimeout(c.sshtimeout),
		server.WithLogger(c.logger),
	}

	// add prefix if set
	if c.prefix != "" {
		if !strings.HasPrefix(c.prefix, "/") {
			return fmt.Errorf("prefix must start with a /")
		}

		opts = append(opts, server.WithPrefix(c.prefix))
	}

	// add any rewrites
	if len(c.rewrites) > 0 {
		rewriteRegex := regexp.MustCompile("^s#([^#\r\n]+)#([^#\r\n]+)#$|^s/([^/\r\n]+)/([^/\r\n]+)/$")
		rewrites := make([]*tunneller.RewriteContentRule, 0)
		for _, r := range c.rewrites {
			sub := rewriteRegex.FindStringSubmatch(r)
			if sub == nil {
				return fmt.Errorf("the provided rewrite was not valid %q", r)
			}

			if len(sub) != 5 {
				return fmt.Errorf("the provided rewrite was not valid %q matches %d", r, len(sub))
			}

			if sub[1] != "" && sub[2] != "" {
				c.logger.Debug("setting up rewrite rule", "regex", sub[1], "template", sub[2])

				re, err := tunneller.NewRewriteContentRule(sub[1], sub[2])
				if err != nil {
					return err
				}

				rewrites = append(rewrites, re)
			} else if sub[3] != "" && sub[4] != "" {
				c.logger.Debug("setting up rewrite rule", "regex", sub[3], "template", sub[4])

				re, err := tunneller.NewRewriteContentRule(sub[3], sub[4])
				if err != nil {
					return err
				}

				rewrites = append(rewrites, re)
			} else {
				return fmt.Errorf("the provided rewrite was not valid (could not find regexp and template)")
			}
		}

		opts = append(opts, server.WithRewriteContentRule(rewrites...))
	}

	// load any ssh keys
	if len(c.keys) > 0 {
		a := agent.NewKeyring()
		for _, keyfile := range c.keys {
			b, err := os.ReadFile(keyfile)
			if err != nil {
				c.logger.Error("could not read private key", "key", keyfile, "error", err)
				continue
			}

			priv, err := ssh.ParseRawPrivateKey(b)
			if err != nil {
				c.logger.Error("could not parse private key", "key", keyfile, "error", err)
				continue
			}

			if err := a.Add(agent.AddedKey{PrivateKey: priv}); err != nil {
				c.logger.Error("could not add key to agent", "key", keyfile, "error", err)
				continue
			}
		}

		l, err := a.List()
		if err != nil {
			c.logger.Error("could not list agent keys", "error", err)
		} else {
			// set up agent if any keys were added
			if len(l) > 0 {
				opts = append(opts, server.WithAgent(a))
			}
		}
	}

	srv, err := server.New(c.sshuser, c.sshhost, c.sshport, opts...)
	if err != nil {
		return err
	}

	srv.AllowedEndpoint = c.allowEndpoint.Regexp()
	srv.AllowedEndpointPort = c.allowEndpointPort.Regexp()
	srv.AllowedEndpointScheme = c.allowEndpointScheme.Regexp()
	srv.AllowedEndpointHeaders = c.allowEndpointHeaders

	// load known hosts file if passed
	if c.sshknownhosts != "" {
		hostKeyCallback, err := knownhosts.New(c.sshknownhosts)
		if err != nil {
			return err
		}
		srv.HostKeyCallback = hostKeyCallback
	} else {
		c.logger.Warn("SSH host key verification is not enabled")
		srv.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	// set up CA pool for HTTPS connections to endpoints
	if c.endpointca != "" {
		if c.endpointca == "@system" {
			rootCAs, err := x509.SystemCertPool()
			if err != nil {
				return err
			}

			srv.ProxyTlsConfig = &tls.Config{
				RootCAs: rootCAs,
			}
		} else {
			caCert, err := os.ReadFile(c.endpointca)
			if err != nil {
				return err
			}

			caCertPool := x509.NewCertPool()
			if !caCertPool.AppendCertsFromPEM(caCert) {
				return fmt.Errorf("failed to append CA certificate to pool")
			}
			srv.ProxyTlsConfig = &tls.Config{
				RootCAs: caCertPool,
			}
		}
	} else {
		c.logger.Warn("certificate verification for HTTPS endpoints is not enabled")
	}

	mux := http.NewServeMux()
	mux.Handle("/{scheme}/{endpoint}/{port}/", srv)
	mux.HandleFunc("/-/healthy", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Healthy"))
	})
	if c.metricspath != "" {
		mux.Handle(c.metricspath, srv.MetricsHandler())
	}
	handler := sloghttp.Recovery(mux)
	handler = sloghttp.New(c.logger)(handler)
	c.mux = handler

	c.logger.Debug("config options set",
		slog.Group("ssh",
			"host", c.sshhost,
			"port", c.sshport,
			"timeout", c.sshtimeout,
			"user", c.sshuser,
			"keys", c.keys,
		),
		slog.Group("endpoint",
			slog.Group("allow",
				"scheme", c.allowEndpointScheme.String(),
				"port", c.allowEndpointPort.String(),
				"endpoint", c.allowEndpoint.String(),
			),
		),
	)

	return nil
}

func (c *rootCommand) Run(ctx context.Context, cd *simplecobra.Commandeer, args []string) error {
	c.logger.Info("starting tunnel-proxy", "addr", c.addr)
	if err := http.ListenAndServe(c.addr, c.mux); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}

	return nil
}

func Execute(ctx context.Context, args []string) error {
	// set up logger
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	rootCmd := &rootCommand{
		Command: vipercommand.New("tunneller", "SSH tunnelling HTTP reverse proxy"),
		logger:  logger,
	}
	rootCmd.EnvPrefix = "tunneller"
	rootCmd.EnvKeyReplacer = strings.NewReplacer(".", "_")
	rootCmd.SubCommands = []simplecobra.Commander{
		&versionCommand{
			Command: simplecommand.New("version", "Print version"),
			logger:  logger,
		},
	}

	// Set up simplecobra
	x, err := simplecobra.New(rootCmd)
	if err != nil {
		return err
	}

	// run command with the provided args
	if _, err := x.Execute(ctx, args); err != nil {
		return err
	}

	return nil
}
