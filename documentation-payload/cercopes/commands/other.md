+++
title = "Other Commands"
chapter = false
weight = 110
+++

## whoami

Get current user information including UID, GID, groups, and elevation status. No arguments.

**MITRE ATT&CK**: T1033 - System Owner/User Discovery

## hostname

Get the system hostname. No arguments.

**MITRE ATT&CK**: T1082 - System Information Discovery

## ps

List running processes with PID, PPID, user, and command line. Reads `/proc` on Linux, uses `tasklist` on Windows. No arguments.

**MITRE ATT&CK**: T1057 - Process Discovery

## cd

Change the agent's working directory.

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | No | `~` | Target directory |

## pwd

Print the agent's current working directory. No arguments.

## ifconfig

List network interfaces with MAC addresses, IPs, and flags. Uses native Go `net.Interfaces()`. No arguments.

**MITRE ATT&CK**: T1016 - System Network Configuration Discovery

## env

List all environment variables (sorted). No arguments.

**MITRE ATT&CK**: T1082 - System Information Discovery

## sleep

Change the agent's callback interval and jitter.

| Argument | Required | Description |
|----------|----------|-------------|
| `interval` | No | New sleep interval in seconds |
| `jitter` | No | New jitter percentage (0-100) |

## exit

Terminate the agent process immediately. No arguments.
