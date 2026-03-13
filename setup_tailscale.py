#!/usr/bin/env python3
"""
Tailscale Setup Script for Tailscale C2 Profile

Provisions all required Tailscale resources:
  1. Validates API key and discovers tailnet
  2. Sets ACL policy (agents can only reach c2-server)
  3. Creates server pre-auth key (tag:c2-server)
  4. Writes config.json for the C2 profile

Usage:
  python3 setup_tailscale.py --api-key tskey-api-...
  python3 setup_tailscale.py --api-key tskey-api-... --hostname mythic-c2 --port 8080
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    print("[!] requests is required. Install with: pip install requests")
    sys.exit(1)

SCRIPT_DIR = Path(__file__).parent
C2_CONFIG_PATH = SCRIPT_DIR / "C2_Profiles" / "tailscale" / "tailscale" / "c2_code" / "config.json"
STATE_FILE = SCRIPT_DIR / ".tailscale_setup_state.json"

TAILSCALE_API = "https://api.tailscale.com/api/v2"

def build_acl_policy(port, tcp_port=None):
    """Build ACL policy restricting agents to only the C2 server's listen ports."""
    # Build list of allowed destination ports
    ports = [port]
    if tcp_port and tcp_port != "0":
        ports.append(tcp_port)
    port_list = ",".join(ports)

    return {
        "acls": [
            {
                "action": "accept",
                "src": ["tag:agent"],
                "dst": [f"tag:c2-server:{port_list}"],
                "comment": "Agents can only reach the C2 server on the configured ports",
            },
            {
                "action": "accept",
                "src": ["tag:c2-server"],
                "dst": [f"tag:agent:{port_list}"],
                "comment": "C2 server can reach agents on the same ports (for reverse connections)",
            },
        ],
        "tagOwners": {
            "tag:c2-server": ["autogroup:admin"],
            "tag:agent": ["autogroup:admin"],
        },
    }


def api(method, path, api_key, json_data=None):
    url = f"{TAILSCALE_API}{path}"
    headers = {"Authorization": f"Bearer {api_key}"}
    resp = requests.request(method, url, headers=headers, json=json_data)
    return resp


def get_tailnet_info(api_key):
    print("[*] Validating API key...")
    # Use "-" as tailnet which auto-resolves
    resp = api("GET", "/tailnet/-/devices", api_key)
    if resp.status_code == 200:
        return True
    elif resp.status_code == 401:
        print(f"[!] Invalid API key")
        sys.exit(1)
    else:
        print(f"[!] API error ({resp.status_code}): {resp.text}")
        sys.exit(1)


def set_acl_policy(api_key, port, tcp_port=None):
    policy = build_acl_policy(port, tcp_port)
    ports_str = port if not tcp_port or tcp_port == "0" else f"{port},{tcp_port}"
    print("[*] Setting ACL policy...")
    print(f"    - tag:agent     -> tag:c2-server:{ports_str} (allow)")
    print(f"    - tag:c2-server -> tag:agent:{ports_str}     (allow)")
    print(f"    - everything else                            (deny)")

    resp = api("POST", "/tailnet/-/acl", api_key, json_data=policy)
    if resp.status_code == 200:
        print("[+] ACL policy set successfully")
    elif resp.status_code == 403:
        print("[!] API key lacks ACL write permission. Set ACLs manually in Tailscale admin console.")
        print("[*] Required policy:")
        print(json.dumps(policy, indent=2))
    else:
        print(f"[!] Failed to set ACL ({resp.status_code}): {resp.text}")
        print("[*] You may need to set ACLs manually in the Tailscale admin console")


def create_server_key(api_key):
    print("[*] Creating server pre-auth key (tag:c2-server, reusable)...")
    payload = {
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": True,
                    "ephemeral": False,
                    "preauthorized": True,
                    "tags": ["tag:c2-server"],
                }
            }
        },
        "expirySeconds": 86400 * 90,  # 90 days
        "description": "Mythic Tailscale C2 server key",
    }

    resp = api("POST", "/tailnet/-/keys", api_key, json_data=payload)
    if resp.status_code != 200:
        print(f"[!] Failed to create server key ({resp.status_code}): {resp.text}")
        sys.exit(1)

    data = resp.json()
    key = data.get("key", "")
    key_id = data.get("id", "")
    expires = data.get("expires", "")
    print(f"[+] Server key created: {key[:20]}...")
    print(f"    ID: {key_id}")
    print(f"    Expires: {expires}")
    return key, key_id


def write_c2_config(api_key, server_auth_key, hostname, port, tcp_port="8081"):
    config = {
        "auth_key": server_auth_key,
        "control_url": "https://controlplane.tailscale.com",
        "hostname": hostname,
        "listen_port": port,
        "tcp_port": tcp_port,
        "api_key": api_key,
        "tailnet": "-",
        "provider": "tailscale",
    }
    C2_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(C2_CONFIG_PATH, "w") as f:
        json.dump(config, f, indent=4)
    print(f"[+] C2 config written to: {C2_CONFIG_PATH}")


def save_state(server_key_id, hostname):
    state = {
        "server_key_id": server_key_id,
        "hostname": hostname,
        "provider": "tailscale",
    }
    with open(STATE_FILE, "w") as f:
        json.dump(state, f, indent=4)


def teardown(api_key):
    if not STATE_FILE.exists():
        print("[!] No setup state found. Nothing to tear down.")
        sys.exit(1)

    with open(STATE_FILE) as f:
        state = json.load(f)

    server_key_id = state.get("server_key_id", "")

    print(f"\n[!] This will:")
    print(f"    - Delete server auth key: {server_key_id}")
    print(f"    - Reset C2 config to empty")
    confirm = input("\n    Type 'yes' to confirm: ")
    if confirm.strip().lower() != "yes":
        print("[*] Aborted.")
        sys.exit(0)

    if server_key_id:
        print(f"[*] Deleting server key {server_key_id}...")
        resp = api("DELETE", f"/tailnet/-/keys/{server_key_id}", api_key)
        if resp.status_code in (200, 204):
            print("[+] Server key deleted")
        else:
            print(f"[!] Failed to delete key ({resp.status_code}): {resp.text}")

    # Reset config
    write_c2_config("", "", "mythic-c2", "8080", "8081")
    STATE_FILE.unlink(missing_ok=True)
    print("[+] Teardown complete")


def setup(args):
    api_key = args.api_key
    hostname = args.hostname
    port = args.port
    tcp_port = args.tcp_port

    if args.teardown:
        teardown(api_key)
        return

    print(f"\n{'=' * 60}")
    print(f"  Tailscale C2 Profile - Setup")
    print(f"{'=' * 60}")
    print(f"  Hostname:    {hostname}")
    print(f"  HTTP Port:   {port}")
    print(f"  TCP Port:    {tcp_port}")
    print(f"  Config:      {C2_CONFIG_PATH}")
    print(f"{'=' * 60}\n")

    # Step 1: Validate API key
    get_tailnet_info(api_key)
    print("[+] API key valid")

    # Step 2: Set ACL policy (restricted to listen ports only)
    set_acl_policy(api_key, port, tcp_port)

    # Step 3: Create server pre-auth key
    server_key, server_key_id = create_server_key(api_key)

    # Step 4: Write config
    write_c2_config(api_key, server_key, hostname, port, tcp_port)

    # Step 5: Save state
    save_state(server_key_id, hostname)

    print(f"\n{'=' * 60}")
    print(f"  Setup Complete!")
    print(f"{'=' * 60}")
    print(f"  Server Hostname: {hostname}")
    print(f"  HTTP Port:       {port}")
    print(f"  TCP Port:        {tcp_port}")
    print(f"  Config written:  {C2_CONFIG_PATH}")
    print(f"")
    print(f"  Next steps:")
    print(f"    1. Restart the tailscale C2 profile in Mythic")
    print(f"       sudo ./mythic-cli c2 start tailscale")
    print(f"    2. Build a cercopes payload")
    print(f"    3. Run the payload on a target")
    print(f"")
    print(f"  To tear down:")
    print(f"    python3 {__file__} --api-key <key> --teardown")
    print(f"{'=' * 60}")


def main():
    parser = argparse.ArgumentParser(
        description="Setup Tailscale resources for C2 Profile",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--api-key", required=True, help="Tailscale API key")
    parser.add_argument("--hostname", default="mythic-c2", help="Server hostname on tailnet (default: mythic-c2)")
    parser.add_argument("--port", default="8080", help="HTTP listen port on tailnet (default: 8080)")
    parser.add_argument("--tcp-port", default="8081", help="TCP listen port on tailnet (default: 8081)")
    parser.add_argument("--teardown", action="store_true", help="Remove created resources")

    args = parser.parse_args()
    setup(args)


if __name__ == "__main__":
    main()
