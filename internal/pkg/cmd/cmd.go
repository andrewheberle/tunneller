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
	addr                string
	keys                []string
	sshhost             string
	sshport             string
	sshuser             string
	sshknownhosts       string
	sshtimeout          time.Duration
	allowJumphost       *regexpflag.Flag
	allowJumphostUser   *regexpflag.Flag
	allowJumphostPort   *regexpflag.Flag
	endpointca          string
	endpointport        string
	endpointscheme      string
	allowEndpoint       *regexpflag.Flag
	allowEndpointPort   *regexpflag.Flag
	allowEndpointScheme *regexpflag.Flag
	debug               bool

	mux    http.Handler
	logger *slog.Logger

	*vipercommand.Command
}

var logLevel = new(slog.LevelVar)

func (c *rootCommand) Init(cd *simplecobra.Commandeer) error {
	if err := c.Command.Init(cd); err != nil {
		return err
	}

	c.allowJumphost = regexpflag.MustCompile(".*")
	c.allowJumphostUser = regexpflag.MustCompile("^jump$")
	c.allowJumphostPort = regexpflag.MustCompile("^22$")
	c.allowEndpoint = regexpflag.MustCompile(".*")
	c.allowEndpointScheme = regexpflag.MustCompile("^http(s)?$")
	c.allowEndpointPort = regexpflag.MustCompile("^(80|443)$")

	cmd := cd.CobraCommand
	cmd.Flags().BoolVar(&c.debug, "debug", false, "Enable debug logging")
	cmd.Flags().StringVar(&c.addr, "addr", ":8080", "Listen address")
	cmd.Flags().StringSliceVar(&c.keys, "key", []string{}, "SSH key(s) to load for authentication")
	cmd.Flags().StringVar(&c.sshhost, "ssh", "", "Default SSH jump host")
	cmd.Flags().StringVar(&c.sshknownhosts, "ssh.knownhosts", "", "SSH known_hosts file to verify jump host identity")
	cmd.Flags().Var(c.allowJumphost, "ssh.allow", "Allowed SSH jump hosts (regexp)")
	cmd.Flags().StringVar(&c.sshuser, "ssh.user", "jump", "Default SSH user to use for jump host")
	cmd.Flags().DurationVar(&c.sshtimeout, "ssh.timeout", time.Minute*5, "Idle timeout for SSH jump host connections")
	cmd.Flags().Var(c.allowJumphostUser, "ssh.user.allow", "Allowed SSH user for jump host (regexp)")
	cmd.Flags().Var(c.allowJumphostPort, "ssh.port.allow", "Allowed SSH port for jump host (regexp)")
	cmd.Flags().StringVar(&c.sshport, "ssh.port", "22", "SSH port for jump host")
	cmd.Flags().Var(c.allowEndpoint, "endpoint.allow", "Allowed remote endpoints (regexp)")
	cmd.Flags().StringVar(&c.endpointca, "endpoint.ca", "", "CA bundle to verify HTTPS connections to endpoints")
	cmd.Flags().StringVar(&c.endpointport, "endpoint.port", "80", "Default endpoint port")
	cmd.Flags().Var(c.allowEndpointPort, "endpoint.port.allow", "Allowed remote endpoint ports (regexp)")
	cmd.Flags().StringVar(&c.endpointscheme, "endpoint.scheme", "http", "Default endpoint scheme")
	cmd.Flags().Var(c.allowEndpointScheme, "endpoint.scheme.allow", "Allowed remote endpoint schemes (regexp)")

	return nil
}

func (c *rootCommand) PreRun(this, runner *simplecobra.Commandeer) error {
	if err := c.Command.PreRun(this, runner); err != nil {
		return err
	}

	if c.debug {
		logLevel.Set(slog.LevelDebug)
	}

	srv := &server.Server{
		Tunnels:               make(map[string]*tunneller.Tunnel),
		AllowedJumphost:       c.allowJumphost.Regexp(),
		AllowedJumphostUser:   c.allowJumphostUser.Regexp(),
		AllowedJumphostPort:   c.allowJumphostPort.Regexp(),
		SSHHost:               c.sshhost,
		SSHPort:               c.sshport,
		SSHUser:               c.sshuser,
		SSHTimeout:            c.sshtimeout,
		AllowedEndpoint:       c.allowEndpoint.Regexp(),
		AllowedEndpointPort:   c.allowEndpointPort.Regexp(),
		AllowedEndpointScheme: c.allowEndpointScheme.Regexp(),
		EndpointPort:          c.endpointport,
		EndpointScheme:        c.endpointscheme,
		Logger:                c.logger,
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
				srv.Agent = a
			}
		}
	}

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
	mux.Handle("/{jumphostuser}/{jumphost}/{jumphostport}/{scheme}/{endpoint}/{port}/", srv)
	mux.Handle("/{jumphostuser}/{jumphost}/{scheme}/{endpoint}/{port}/", srv)
	mux.Handle("/{jumphost}/{scheme}/{endpoint}/{port}/", srv)
	mux.Handle("/{jumphost}/{scheme}/{endpoint}/", srv)
	mux.Handle("/{jumphost}/{endpoint}/", srv)
	mux.Handle("/{endpoint}/", srv)
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
			slog.Group("allow",
				"host", c.allowJumphost.String(),
				"port", c.allowJumphostPort.String(),
				"user", c.allowJumphostUser.String(),
			),
		),
		slog.Group("endpoint",
			"scheme", c.endpointscheme,
			"port", c.endpointport,
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
