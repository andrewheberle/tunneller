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
| `--key` | | SSH private key file(s) to load for authentication (repeatable) |
| `--ssh` | | Default SSH jump host |
| `--ssh.allow` | `.*` | Allowed SSH jump hosts (regexp) |
| `--ssh.knownhosts` | | SSH known_hosts file to verify jump host identity |
| `--ssh.user` | `jump` | Default SSH user |
| `--ssh.user.allow` | `^jump$` | Allowed SSH users (regexp) |
| `--ssh.port` | `22` | Default SSH jump host port |
| `--ssh.port.allow` | `^22$` | Allowed SSH jump host ports (regexp) |
| `--ssh.timeout` | `5m` | Idle timeout for SSH jump host connections |
| `--endpoint.allow` | `.*` | Allowed remote endpoints (regexp) |
| `--endpoint.ca` | | CA bundle to verify HTTPS connections to endpoints |
| `--endpoint.port` | `80` | Default endpoint port |
| `--endpoint.port.allow` | `^(80\|443)$` | Allowed endpoint ports (regexp) |
| `--endpoint.scheme` | `http` | Default endpoint scheme |
| `--endpoint.scheme.allow` | `^http(s)?$` | Allowed endpoint schemes (regexp) |

#### Setting Flags from the Environment

All flags can be set using the following form:

`TUNNELLER_<FLAG NAME>`

For example:

```sh
TUNNELLER_SSH_TIMEOUT="15m" TUNNELLER_KEY="/etc/tunneller/id_ed25519" tunneller
```

Command line and environment variables may be combined with environment variables
taking precedence over command line flags.

### Authentication

SSH authentication uses private keys loaded at startup via one or more `--key` flags.
Keys are held in an in-process SSH agent for the lifetime of the service.

```
tunneller --key /etc/tunneller/id_ed25519 --key /etc/tunneller/id_rsa
```

If no keys are loaded then authentication will fail.

## URL Routing

The request URL determines the tunnel parameters. Six route forms are supported, from
most specific to least specific. Less specific forms rely on defaults set via command line
flags or environment variables.

### Route forms

```
/{endpoint}/
/{jumphost}/{endpoint}/
/{jumphost}/{scheme}/{endpoint}/
/{jumphost}/{scheme}/{endpoint}/{port}/
/{jumphostuser}/{jumphost}/{scheme}/{endpoint}/{port}/
/{jumphostuser}/{jumphost}/{jumphostport}/{scheme}/{endpoint}/{port}/
```

| Parameter | Description | Default flag |
|-----------|-------------|--------------|
| `endpoint` | Remote host to reach via the tunnel | (required) |
| `jumphost` | SSH jump host address | `--ssh` |
| `jumphostuser` | SSH user for the jump host | `--ssh.user` |
| `jumphostport` | SSH port for the jump host | `--ssh.port` |
| `scheme` | Endpoint scheme (`http` or `https`) | `--endpoint.scheme` |
| `port` | Endpoint port | `--endpoint.port` |

### Examples

Given a service started with:

```
tunneller \
  --ssh jump.example.com \
  --ssh.user jump \
  --endpoint.scheme https \
  --endpoint.port 443
```

| URL | Connects to |
|-----|-------------|
| `/192.168.1.1/` | `https://192.168.1.1:443` via `jump@jump.example.com:22` |
| `/jump2.example.com/192.168.1.1/` | `https://192.168.1.1:443` via `jump@jump2.example.com:22` |
| `/jump2.example.com/http/192.168.1.1/` | `http://192.168.1.1:443` via `jump@jump2.example.com:22` |
| `/jump2.example.com/http/192.168.1.1/80/` | `http://192.168.1.1:80` via `jump@jump2.example.com:22` |
| `/admin/jump2.example.com/http/192.168.1.1/80/` | `http://192.168.1.1:80` via `admin@jump2.example.com:22` |
| `/admin/jump2.example.com/2222/http/192.168.1.1/80/` | `http://192.168.1.1:80` via `admin@jump2.example.com:2222` |

## Restrictions

All URL parameters are validated against their corresponding `--*.allow` regexp flags before a tunnel is established. Requests that fail validation receive a `403 Forbidden` response.

This allows the operator to constrain which jump hosts, users, ports, schemes, and endpoints are reachable through the service. For example, to restrict the service to a single jump host and only allow HTTPS to RFC 1918 addresses:

```
tunneller \
  --ssh jump.example.com \
  --ssh.allow '^jump\.example\.com$' \
  --endpoint.allow '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)' \
  --endpoint.scheme https \
  --endpoint.scheme.allow '^https$' \
  --endpoint.port 443 \
  --endpoint.port.allow '^443$'
```

## Tunnel Lifecycle

A tunnel is established on the first request to a given parameter combination and reused for subsequent requests with the same parameters. Tunnels are torn down automatically after a period of inactivity (idle timeout). A new tunnel will be established if a subsequent request arrives after teardown.

## SSH Host Key Verification

By default SSH host keys are **not** verified, which is not secure in production.

The `--ssh.knownhosts` option accepts the path to a SSH Known Hosts file in order
to verify host keys.

## Endpoint Certificate Verification

Enabling certificate verification for HTTPS is highly recommended by passing the
`--endpoint.ca` option which accepts a path to a CA bundle in PEM format or the
special value `@system` which loads trusted CA's from the system (if available).
