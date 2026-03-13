+++
title = "Tailscale C2"
chapter = false
weight = 5
+++

## Overview

The Tailscale C2 profile provides command and control communication over a Tailscale or Headscale mesh VPN network. All agent traffic is transported inside WireGuard-encrypted tunnels, making it indistinguishable from normal Tailscale traffic.

The C2 server joins the same tailnet as the agent and exposes an HTTP endpoint within the mesh. The agent connects to this endpoint using an embedded `tsnet` client, so no Tailscale daemon is required on the target host.

## Architecture

```
Target Host                    Tailnet (WireGuard)             Mythic Infrastructure
+-----------+                  +-------------------+           +----------------+
|  Agent    | -- tsnet ------> | Tailscale/         | <------- | C2 Server      |
| (tsnet    |    encrypted     | Headscale          |  tsnet   | (Go, tsnet)    |
|  client)  |    tunnel        | Control Plane      |          |   :8080        |
+-----------+                  +-------------------+           +-------+--------+
                                                                       |
                                                                       | HTTP forward
                                                                       v
                                                               +----------------+
                                                               | Mythic Server  |
                                                               |  :17443        |
                                                               +----------------+
```

## Profile Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `callback_interval` | String | `5` | Agent callback interval in seconds |
| `callback_jitter` | String | `10` | Jitter percentage (0-100) |
| `encrypted_exchange_check` | ChooseOne | `T` | Enable Mythic encrypted key exchange |
| `AESPSK` | Crypto | `aes256_hmac` | Encryption type (`aes256_hmac` or `none`) |
| `killdate` | Date | (empty) | Agent expiration date |

## Server Configuration

The C2 server reads its configuration from `config.json` or environment variables:

| Config Key | Environment Variable | Default | Description |
|------------|---------------------|---------|-------------|
| `auth_key` | `TS_AUTH_KEY` | (required) | Tailscale/Headscale pre-auth key for the server |
| `control_url` | `TS_CONTROL_URL` | (empty = Tailscale cloud) | Control plane URL |
| `hostname` | `TS_HOSTNAME` | `mythic-c2` | Server's hostname on the tailnet |
| `listen_port` | `TS_LISTEN_PORT` | `8080` | HTTP listener port within the tailnet |
| `tcp_port` | `TS_TCP_PORT` | (empty) | TCP listener port within the tailnet (enables raw TCP transport) |
| `api_key` | (config only) | (required) | API key for generating per-agent pre-auth keys |
| `tailnet` | (config only) | `-` | Tailnet name (use `-` for default) |
| `provider` | (config only) | `tailscale` | `tailscale` or `headscale` |

## Headscale vs Tailscale

The profile supports both providers:

- **Tailscale (cloud)**: Uses `api.tailscale.com` for key generation. Set `provider: "tailscale"` and provide an API key with device auth scope.
- **Headscale (self-hosted)**: Uses your Headscale instance's API. Set `provider: "headscale"`, `control_url` to your Headscale URL, and `api_key` to a Headscale API key.

## How Pre-Auth Keys Work

At payload build time, Mythic calls the `generate_config` RPC on this profile. The profile contacts the Tailscale/Headscale API to create an **ephemeral, reusable pre-auth key** scoped to `tag:agent`. This key is stamped into the agent binary at compile time.

When the agent starts, it uses this key to authenticate to the tailnet without any user interaction. Since the key creates ephemeral devices, the agent's node is automatically removed from the tailnet when it disconnects.

## Transport Protocols

The C2 server supports two transport protocols. Which one the agent uses is selected via the agent's `tailscale_protocol` build parameter — not a C2 profile setting. This way agents that only implement HTTP won't expose a TCP option.

### HTTP (default)

Standard HTTP POST to `http://<hostname>:<listen_port>/agent_message`. Compatible with any agent.

### Raw TCP (lower overhead)

Persistent TCP connection to `<hostname>:<tcp_port>` with length-prefixed binary framing:

```
[4-byte big-endian length][payload bytes]
```

The payload is the same `base64(UUID + JSON)` used by HTTP. TCP eliminates HTTP header overhead and per-request connection setup. Since all traffic is already WireGuard-encrypted, the HTTP framing adds no security value.

Requires `tcp_port` to be set in `config.json`. Agents must explicitly implement TCP support (cercopes and Kassandra do).

## Message Flow

**HTTP mode:**
1. Agent sends `base64(UUID + JSON)` via HTTP POST to `http://mythic-c2:8080/agent_message`
2. C2 server receives the request over the tailnet
3. C2 server forwards the raw body to Mythic at `http://mythic_server:17443/agent_message`
4. Mythic processes and returns a response
5. C2 server relays the response back to the agent

**TCP mode:**
1. Agent writes `[4-byte length][base64(UUID + JSON)]` over the persistent TCP connection
2. C2 server reads the framed message
3. C2 server forwards the raw payload to Mythic via HTTP (same as above)
4. C2 server writes `[4-byte length][response]` back to the agent

All traffic between agent and C2 server is encrypted by WireGuard at the transport layer. Optional AES-256 encryption provides an additional application-layer security envelope.

## OPSEC

### Disk Artifacts

Agents using embedded tsnet must avoid writing to default state directories:

| OS | Default tsnet path (avoid) |
|----|---------------------------|
| Windows | `%APPDATA%\tsnet-<hostname>\` |
| Linux | `~/.config/tsnet-<hostname>/` |
| macOS | `~/Library/Application Support/tsnet-<hostname>/` |

These directories contain WireGuard keys, logs, and state files that immediately identify the process as a Tailscale client. Agents must: use a temp directory for `Dir`, use `mem.Store` for key storage, suppress logging, and clean up on exit.

### Outbound Connection Overview

A firewall or network monitor observing the agent process sees the following connections:

**Startup (one-time):**

```
Agent ──HTTPS──▶ controlplane.tailscale.com:443     Registration, key exchange, peer discovery
Agent ──UDP────▶ derpN.tailscale.com:3478             STUN — NAT type detection / hole-punching
```

**Steady state — direct WireGuard (NAT traversal succeeds):**

```
Agent ──UDP────▶ <C2 server IP>:41641                 Direct WireGuard tunnel (single persistent flow)
```

**Steady state — relayed (corporate firewall blocks UDP):**

```
Agent ──HTTPS──▶ derpN.tailscale.com:443              WireGuard over WebSocket relay
```

#### Full Connection Table

| Phase | Destination | Port | Protocol | Purpose |
|-------|------------|------|----------|---------|
| Startup | `controlplane.tailscale.com` | 443 | HTTPS | Node registration & coordination |
| Startup | `login.tailscale.com` | 443 | HTTPS | Auth (may be skipped with pre-auth key) |
| Startup | `derpN.tailscale.com` | 3478 | UDP | STUN NAT detection |
| Data | C2 server's public IP | 41641 | UDP | Direct WireGuard tunnel |
| Data | `derpN.tailscale.com` | 443 | HTTPS | DERP relay fallback |
| DNS | System resolver | 53 | UDP | Resolve Tailscale hostnames |

With **Headscale**: replace all `tailscale.com` destinations with your self-hosted domain. DERP relays can also be self-hosted, making the entire traffic pattern point to operator-controlled infrastructure.

#### DNS-over-HTTPS (DoH)

The DNS row in the table above is the most obvious fingerprint — corporate DNS logs will show queries for `controlplane.tailscale.com` and `derpN.tailscale.com` before the agent even connects.

Agents that support it (cercopes, Kassandra) have a `doh` build parameter:

| Choice | DoH Resolver | Effect |
|--------|-------------|--------|
| `off` | System DNS | Default — queries visible in DNS logs |
| `cloudflare` | `https://1.1.1.1/dns-query` | DNS over HTTPS to Cloudflare |
| `google` | `https://8.8.8.8/dns-query` | DNS over HTTPS to Google |
| `custom` | `doh_url` build parameter | Your own DoH resolver |

When enabled, DNS queries for Tailscale-related domains are sent as encrypted HTTPS requests (RFC 8484) to the DoH resolver. The corporate DNS server never sees `tailscale.com`. Specifically, the following domains are routed through DoH:

- `*.tailscale.com` — control plane, logging, and DERP relay hostnames
- The Headscale control URL hostname (automatically extracted from `control_url`)

All other DNS queries use the **system resolver**, so internal/corporate domain resolution remains fully functional. This selective approach avoids breaking local name resolution while hiding only the Tailscale fingerprint.

#### Detection Risk

| Environment | Traffic pattern | Risk |
|------------|----------------|------|
| Enterprise with Tailscale deployed | Blends with legitimate Tailscale users | Low |
| Enterprise without Tailscale | `tailscale.com` domains in DNS logs | Medium — use Headscale or DoH |
| With DoH enabled | No Tailscale DNS queries, HTTPS to DoH resolver | Low |
| With self-hosted Headscale + DERP | All traffic to operator infrastructure | Low |

### Node Visibility

- Agents join the tailnet as **ephemeral nodes** — automatically removed on disconnect
- Pre-auth keys are scoped to `tag:agent` with ACLs restricting access to only the C2 server's listen port(s)
