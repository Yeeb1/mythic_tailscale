+++
title = "Cercopes"
chapter = true
weight = 5
+++

## Cercopes Agent

Cercopes is a lightweight, cross-platform Mythic agent written in Go that communicates exclusively over Tailscale/Headscale mesh VPN networks using an embedded `tsnet` client.

### Key Features

- **Embedded VPN**: Uses `tsnet` to join a Tailscale/Headscale network directly from the process, no Tailscale daemon required on the target
- **In-memory state**: All Tailscale state is kept in memory (`mem.Store`), nothing persists to disk
- **Ephemeral nodes**: Automatically deregisters from the tailnet on exit
- **Cross-platform**: Supports Linux, Windows, and macOS
- **SOCKS5 proxy**: Built-in SOCKS5 support for pivoting through the agent
- **WireGuard transport**: All C2 traffic is encrypted inside WireGuard tunnels

### Supported Operating Systems

| OS | Architecture |
|----|-------------|
| Linux | amd64, arm64 |
| Windows | amd64, arm64 |
| macOS | amd64, arm64 |

### Build Parameters

| Parameter | Choices | Default | Description |
|-----------|---------|---------|-------------|
| `architecture` | amd64, arm64 | amd64 | Target CPU architecture |

The target OS is automatically set based on the OS selected in Mythic's payload creation UI.

{{% children %}}
