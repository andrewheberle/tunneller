# tunneller

`tunneller` is an HTTP reverse proxy that forwards requests to remote endpoints via SSH tunnels.
Tunnels are established on demand and torn down automatically after a period of inactivity.

The target endpoint, SSH jump host, and related parameters can be supplied via the request URL,
with defaults and restrictions configured at startup via command line flags.

## Usage

```sh
tunneller [flags]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `:8080` | Listen address |
| `--endpoint.allow` | `.*` | Allowed remote endpoints (regexp) |
| `--endpoint.ca` | | CA bundle to verify HTTPS connections to endpoints |
| `--endpoint.headers.allow` | `Accept`, `Accept-Encoding`, `Accept-Language`, `Authorization`, `Cache-Control`, `Connection`, `Content-Length`, `Content-Type`, `Cookie`, `Origin`, `Referer`, `Upgrade-Insecure-Requests`, `User-Agent` | Allowed HTTP headers to pass to endpoint (canonical form). Host header is always allowed. |
| `--endpoint.html.rewrite` | | Rewrites to apply to `text/html` content (see below for details) |
| `--endpoint.port.allow` | `^(80\|443)$` | Allowed endpoint ports (regexp) |
| `--endpoint.scheme.allow` | `^http(s)?$` | Allowed endpoint schemes (regexp) |
| `--prefix` | | Prefix for HTTP proxy endpoint |
| `--ssh` | | SSH jump host address |
| `--ssh.key` | | SSH private key file(s) to load for jump host authentication (repeatable) |
| `--ssh.knownhosts` | | SSH known_hosts file to verify jump host identity |
| `--ssh.user` | `jump` | SSH jump host user |
| `--ssh.port` | `22` | SSH jump host port |
| `--ssh.timeout` | `5m` | Idle timeout for SSH jump host connections |

#### Setting Flags from the Environment

All flags can be set using the following form:

`TUNNELLER_<FLAG NAME>`

For example:

```sh
TUNNELLER_SSH_TIMEOUT="15m" TUNNELLER_SSH_KEY="/etc/tunneller/id_ed25519" tunneller
```

Command line and environment variables may be combined with environment variables
taking precedence over command line flags.

### Authentication

SSH authentication uses private keys loaded at startup via one or more `--key` flags.
Keys are held in an in-process SSH agent for the lifetime of the service.

```
tunneller --ssh.key /etc/tunneller/id_ed25519 --ssh.key /etc/tunneller/id_rsa
```

If no keys are loaded then authentication will fail.

## URL Routing

The request URL determines the tunnel parameters in the form of:

```
/{scheme}/{endpoint}/{port}/
```

| Parameter | Description | Default flag |
|-----------|-------------|--------------|
| `endpoint` | Remote host to reach via the tunnel | (required) |
| `scheme` | Endpoint scheme (required) | |
| `port` | Endpoint port | (required) |

### Examples

Given a service started with:

```
tunneller \
  --ssh jump.example.com \
  --ssh.user jump \
```

| URL | Connects to |
|-----|-------------|
| `/http/192.168.1.1/80/` | `http://192.168.1.1:80` via `jump@jump.example.com:22` |
| `/https/192.168.1.2/443/` | `https://192.168.1.2:443` via `jump@jump.example.com:22` |

## Restrictions

All URL parameters are validated against their corresponding `--*.allow` regexp flags before a tunnel is established. Requests that fail validation receive a `403 Forbidden` response.

This allows the operator to constrain which jump hosts, users, ports, schemes, and endpoints are reachable through the service. For example, to restrict the service to a single jump host and only allow HTTPS to RFC 1918 addresses on port 443:

```
tunneller \
  --ssh jump.example.com \
  --ssh.allow '^jump\.example\.com$' \
  --endpoint.allow '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' \
  --endpoint.scheme.allow '^https$' \
  --endpoint.port.allow '^443$'
```

## Tunnel Lifecycle

A tunnel is established on the first request to a given parameter combination and
reused for subsequent requests with the same parameters. Tunnels are torn down
automatically after a period of inactivity (idle timeout). A new tunnel will be
established if a subsequent request arrives after teardown.

## SSH Host Key Verification

By default SSH host keys are **not** verified, which is not secure in production.

The `--ssh.knownhosts` option accepts the path to a SSH Known Hosts file in order
to verify host keys.

## Endpoint Certificate Verification

Enabling certificate verification for HTTPS is highly recommended by passing the
`--endpoint.ca` option which accepts a path to a CA bundle in PEM format or the
special value `@system` which loads trusted CA's from the system (if available).

## Cookie Handling

Any cookies that are returned from the proxied endpoint via a `Set-Cookie` header
have their `path` value changed so they are only valid for the proxied path.

In addition only cookies that have been returned from a proxied endpoint via a
`Set-Cookie` header will be passed from the browser to the remote endpoint.

This "cookie tracking" is per tunnel but is maintained for the lifetime of the
entire service, not just the lifetime of the particular tunnel.

## Metrics

Prometheus metrics are provided at the `/metrics` endpoint by default but can
be changed using the `--metrics.path` flag or disabled completely with the
`--metrics.enabled` flag.

| Metric Name                          | Type    | Description |
|--------------------------------------|---------|-------------|
| `tunneller_tunnel_count`             | Guage   | Number of active SSH tunnels |
| `tunneller_tunnel_established_total` | Counter | Total number of SSH tunnels established successfully |
| `tunneller_tunnel_error_total`       | Counter | Total number of errors when establishing SSH tunnels |
| `tunneller_tunnel_total`             | Counter | Total number of SSH tunnels attempted to be established |

## Content Rewrites

By default `action`, `href` and `src` properties that reference absolute paths
will be rewritten based on the prefix used to connect to the endpoint.

In addition, custom content rewrites can be provided via the
`--endpoint.html.rewrite` option as follows:

```sh
tunneller --endpoint.html.rewrite "s#regex#template#"
```

The `regex` is a Go RE2 regular expression that must contain a valid RE2
regular expression that will match at most one substring.

For example, althrough all of the following three regular expressions are
valid however only the first two will work as expected:

```re
foo="([^"\n\r]*)"
foo=("[^"\n\r]*")|foo=('[^'\n\r]*')
(foo|bar)="([^"\n\r]*)"
```

The last form will not yield the expected results and unfortuantely will not
cause a parsing error.

Template is a Go `template` that is passed the URL prefix as `{{ .Prefix }}`
and the captured string as `{{ .Captured }}`.

The overall syntax is somewhat inspired by `sed` with the seperator between
regexp and template being `#` or `/`.

The unmatched content of the regexp is wrapped back around the templated
response.

So for example to replace absolute URLs in all `href` properties a rewrite
as follows may be appropriate:

```sh
tunneller --endpoint.html.rewrite 's#href=["'](/.*)["']#{{ .Prefix }}{{ .Captured }}#'
```

The above would make the following changes for a device accessed via the
URL path of `/https/192.168.10.1/443/` as follows:

```html
<a href="relative/link">This is unchanged</a>
<a href="/absolute/link">This will be updated</a>
```

Would become:

```html
<a href="relative/link">This is unchanged</a>
<a href="/https/192.168.10.1/443/absolute/link">This will be updated</a>
```
