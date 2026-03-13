#!/usr/bin/env python3
"""Wrapper to build (if needed) and start the Go tsnet server binary."""
import os
import shutil
import subprocess
import sys

script_dir = os.path.dirname(os.path.abspath(__file__))
server_bin = os.path.join(script_dir, "server")
cached_bin = "/opt/server"

if not os.path.isfile(server_bin):
    # Try to rebuild from warm cache (fast ~5s), fall back to pre-built binary
    print("[*] Building server binary...", flush=True)
    result = subprocess.run(
        ["go", "build", "-ldflags", "-s -w", "-o", server_bin, "."],
        cwd=script_dir,
        env={**os.environ, "CGO_ENABLED": "0"},
    )
    if result.returncode != 0:
        if os.path.isfile(cached_bin):
            print("[!] Go build failed, using cached binary", flush=True)
            shutil.copy2(cached_bin, server_bin)
        else:
            print("[!] Go build failed and no cached binary available", file=sys.stderr)
            sys.exit(1)
    else:
        print("[+] Server binary built successfully", flush=True)

os.execv(server_bin, [server_bin])
