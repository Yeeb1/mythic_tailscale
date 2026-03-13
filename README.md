# Tailscale C2 for Mythic

A Mythic C2 profile and demo agent that routes all command and control traffic over Tailscale/Headscale mesh VPN networks using WireGuard encryption.

## Components

### Tailscale C2 Profile

A Mythic C2 profile that runs a Go server inside a Tailscale network. The server receives agent messages over the tailnet and forwards them to the Mythic server.

- Supports both **Tailscale** (cloud) and **Headscale** (self-hosted) control planes
- **HTTP and TCP** transport protocols inside the WireGuard tunnel (selectable per agent)
- Generates **ephemeral pre-auth keys** per payload at build time
- Agents join the tailnet as ephemeral nodes — automatically cleaned up on disconnect
- All traffic encrypted by WireGuard at the transport layer

### Cercopes (Demo Agent)

A lightweight, cross-platform Mythic agent written in Go that embeds a `tsnet` client for communication.

- Cross-platform: Linux, Windows, macOS (amd64/arm64)
- In-memory Tailscale state — no files written to disk
- Built-in commands: `shell`, `ls`, `cat`, `cd`, `pwd`, `ps`, `whoami`, `hostname`, `ifconfig`, `env`, `sleep`
- SOCKS5 proxy support for pivoting

## Quick Start

### Prerequisites

- A running [Mythic](https://github.com/its-a-feature/Mythic) instance
- A Tailscale account or self-hosted Headscale server
- An API key with device auth scope

### Installation

```bash
# From the Mythic directory
sudo ./mythic-cli install folder /path/to/tailscale_c2 -f
```

### Configuration

1. After installation, configure the C2 profile's `config.json`:

```json
{
  "auth_key": "tskey-auth-...",
  "control_url": "",
  "hostname": "mythic-c2",
  "listen_port": "8080",
  "tcp_port": "8081",
  "api_key": "tskey-api-...",
  "tailnet": "-",
  "provider": "tailscale"
}
```

For Headscale, set `provider` to `"headscale"` and `control_url` to your Headscale URL.

2. Start the C2 profile from the Mythic UI.

3. Create a new payload selecting the **tailscale** C2 profile and **cercopes** payload type.

4. Deploy the generated binary on the target.

## Integrating Tailscale into Other Agents

The Tailscale C2 profile is agent-agnostic. Any Mythic agent can use it by embedding a Tailscale client and sending standard Mythic HTTP messages through the tailnet.

### libtailscale

This project builds on [libtailscale](https://github.com/tailscale/libtailscale), Tailscale's official C library for embedding Tailscale into applications. libtailscale wraps the Go `tsnet` package and exposes a C API (`tailscale_new`, `tailscale_dial`, `tailscale_listen`, etc.) that can be called from any language with C FFI support.

Integration options by language:

| Approach | Languages | How |
|----------|-----------|-----|
| **Direct `tsnet` import** | Go | Import `tailscale.com/tsnet` — no FFI needed |
| **Go `c-archive` FFI** | Rust, C, C++ | Build a thin Go wrapper as a static library, link via FFI |
| **libtailscale C API** | Any with C FFI | Use `tailscale.h` directly via P/Invoke, ctypes, FFI gems, etc. |
| **libtailscale Python bindings** | Python | Use the pybind11 bindings from the libtailscale repo |
| **libtailscale Ruby bindings** | Ruby | Use the FFI-based gem from the libtailscale repo |
| **TailscaleKit (Swift)** | Swift | Use the native Swift framework from the libtailscale repo |
| **Sidecar** | Any | Run `tailscale up` as a separate process, use regular HTTP |

See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md) for a complete protocol specification and step-by-step integration guide.

### Existing Integrations

| Agent | Language | Integration Method |
|-------|----------|-------------------|
| Cercopes | Go | Direct `tsnet` import |
| Kassandra | Rust | Go FFI static library via `c-archive` |

## Project Structure

```
tailscale_c2/
  C2_Profiles/tailscale/        # C2 profile (Python + Go server)
    tailscale/c2_functions/     #   Profile definition + RPC handlers
    tailscale/c2_code/          #   Go HTTP server + launcher
  Payload_Type/cercopes/        # Demo agent (Go)
    cercopes/agent_functions/   #   Command definitions + builder
    cercopes/agent_code/        #   Go agent source
  documentation-c2/             # Mythic C2 profile docs
  documentation-payload/        # Mythic agent docs
```

## Security Considerations

- Pre-auth keys are ephemeral and scoped to `tag:agent` — they cannot access other devices on the tailnet unless ACLs permit it
- The C2 server is stateless — it proxies HTTP/TCP traffic to Mythic
- Agent nodes are ephemeral — they disappear from the tailnet on disconnect
- WireGuard provides authenticated encryption at the transport layer
- Optional AES-256-HMAC provides application-layer encryption on top

## OPSEC

### Disk Artifacts

By default, tsnet creates a working directory at predictable, well-known paths (`%APPDATA%\tsnet-<hostname>\` on Windows, `~/.config/tsnet-<hostname>/` on Linux). This directory contains WireGuard keys, log files, and internal state — all immediately identifiable as Tailscale artifacts.

**All agent implementations must:**

1. **Set `Dir` to a temporary directory** — avoids the obvious `tsnet-*` path in user-config directories
2. **Use `mem.Store`** — keeps WireGuard keys in memory only
3. **Suppress logging** — set `Logf` to a no-op to prevent log files in `Dir`
4. **Clean up on exit** — remove the temp directory when the agent terminates

Cercopes and the Kassandra FFI wrapper both implement these mitigations. See the [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md#opsec) for details and code examples.

### Network Fingerprint

Outbound connections from the agent process:

| Phase | Destination | Port | Protocol | Purpose |
|-------|------------|------|----------|---------|
| Startup | `controlplane.tailscale.com` | 443 | HTTPS | Registration & key exchange |
| Startup | `derpN.tailscale.com` | 3478 | UDP | STUN / NAT traversal |
| Data | C2 server IP | 41641 | UDP | Direct WireGuard tunnel (if reachable) |
| Data | `derpN.tailscale.com` | 443 | HTTPS | DERP relay fallback (if direct fails) |

- In environments where Tailscale is already deployed, agent traffic blends with legitimate users
- In environments without Tailscale, the `tailscale.com` domains are a fingerprint — use **Headscale** with self-hosted DERP relays to point all traffic to operator-controlled infrastructure

### DNS-over-HTTPS (DoH)

Agents support an optional `doh` build parameter that selectively routes Tailscale-related DNS through an encrypted HTTPS resolver (Cloudflare `1.1.1.1` or Google `8.8.8.8`). This prevents `controlplane.tailscale.com` and DERP server hostnames from appearing in corporate DNS logs — often the most obvious network fingerprint. Only `*.tailscale.com` and the Headscale control URL hostname are routed through DoH; all other DNS queries use the system resolver so internal/corporate domain resolution remains functional.

The DoH implementation patches tsnet's internal `dnscache` singleton (`dnscache.Get().Forward`) which is the actual resolver used by the control plane and logging clients. This is combined with `net.DefaultResolver` and `http.DefaultTransport.DialContext` overrides for full coverage.

| Build Parameter | Resolver | DNS Queries Visible |
|----------------|----------|-------------------|
| `doh: off` | System DNS | Yes — `tailscale.com` in DNS logs |
| `doh: cloudflare` | `https://1.1.1.1/dns-query` | No — encrypted via HTTPS |
| `doh: google` | `https://8.8.8.8/dns-query` | No — encrypted via HTTPS |
| `doh: custom` | `doh_url` build parameter | No — your own resolver |

- See [IMPLEMENTATION_GUIDE.md](IMPLEMENTATION_GUIDE.md#opsec) for the full connection breakdown and implementation details

## License

See individual component licenses.
