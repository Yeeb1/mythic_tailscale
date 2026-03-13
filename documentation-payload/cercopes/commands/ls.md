+++
title = "ls"
chapter = false
weight = 101
+++

## Summary

List directory contents with permissions, size, and modification time. Uses native Go `os.ReadDir`, no shell execution.

## Arguments

| Argument | Required | Default | Description |
|----------|----------|---------|-------------|
| `path` | No | `.` (cwd) | Directory to list |

## Usage

```
ls
ls /tmp
ls /home/user/.ssh
```

## MITRE ATT&CK Mapping

- T1083 - File and Directory Discovery
