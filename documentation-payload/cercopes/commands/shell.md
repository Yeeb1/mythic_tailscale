+++
title = "shell"
chapter = false
weight = 100
+++

## Summary

Execute an operating system command via the default shell (`/bin/sh -c` on Linux/macOS, `cmd.exe /C` on Windows).

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `command` | Yes | The command string to execute |

## Usage

```
shell whoami
shell ls -la /tmp
shell netstat -an
```

## MITRE ATT&CK Mapping

- T1059 - Command and Scripting Interpreter
