+++
title = "cat"
chapter = false
weight = 102
+++

## Summary

Read and display file contents. Output is capped at 1MB to avoid overwhelming the C2 channel. Uses native Go `os.ReadFile`, no shell execution.

## Arguments

| Argument | Required | Description |
|----------|----------|-------------|
| `path` | Yes | File path to read |

## Usage

```
cat /etc/passwd
cat /etc/hostname
cat ~/.bash_history
```

## MITRE ATT&CK Mapping

- T1005 - Data from Local System
