import json
import aiohttp
from pathlib import Path
from mythic_container.C2ProfileBase import *


async def generate_config(input: C2OtherServiceRPCMessage) -> C2OtherServiceRPCMessageResponse:
    """Called at build time to provision a unique pre-auth key for this payload."""
    response = C2OtherServiceRPCMessageResponse(Success=True)

    try:
        config_path = Path(".") / "tailscale" / "c2_code" / "config.json"
        with open(config_path) as f:
            config = json.load(f)

        provider = config.get("provider", "headscale")
        api_key = config.get("api_key", "")
        control_url = config.get("control_url", "")
        hostname = config.get("hostname", "mythic-c2")
        listen_port = config.get("listen_port", "8080")
        tcp_port = config.get("tcp_port", "")

        if not api_key:
            response.Success = False
            response.Error = "No api_key configured in config.json"
            return response

        # Create ephemeral, reusable pre-auth key with tag:agent
        if provider == "headscale":
            auth_key = await _create_headscale_key(control_url, api_key)
        else:
            tailnet = config.get("tailnet", "")
            if not tailnet:
                response.Success = False
                response.Error = "No tailnet configured for Tailscale provider"
                return response
            auth_key = await _create_tailscale_key(api_key, tailnet)

        response.Result = json.dumps({
            "auth_key": auth_key,
            "control_url": control_url,
            "server_hostname": hostname,
            "server_port": listen_port,
            "tcp_port": tcp_port,
        })

    except Exception as e:
        response.Success = False
        response.Error = str(e)

    return response


async def _create_headscale_key(control_url: str, api_key: str) -> str:
    """Create a pre-auth key via Headscale API."""
    url = f"{control_url.rstrip('/')}/api/v1/preauthkey"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "user": "mythic",
        "reusable": True,
        "ephemeral": True,
        "aclTags": ["tag:agent"],
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers, ssl=False) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise Exception(f"Headscale API error ({resp.status}): {text}")
            data = await resp.json()
            return data.get("preAuthKey", {}).get("key", data.get("key", ""))


async def _create_tailscale_key(api_key: str, tailnet: str) -> str:
    """Create a pre-auth key via Tailscale API."""
    url = f"https://api.tailscale.com/api/v2/tailnet/{tailnet}/keys"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "capabilities": {
            "devices": {
                "create": {
                    "reusable": True,
                    "ephemeral": True,
                    "tags": ["tag:agent"],
                }
            }
        },
        "expirySeconds": 86400 * 90,  # 90 days
    }

    async with aiohttp.ClientSession() as session:
        async with session.post(url, json=payload, headers=headers) as resp:
            if resp.status != 200:
                text = await resp.text()
                raise Exception(f"Tailscale API error ({resp.status}): {text}")
            data = await resp.json()
            return data["key"]


class TailscaleC2(C2Profile):
    name = "tailscale"
    description = "Tailscale/Headscale mesh VPN C2 profile using tsnet for WireGuard-encrypted transport"
    author = "@Yeeb1"
    is_p2p = False
    is_server_routed = False
    mythic_encrypts = True
    server_folder_path = Path(".") / "tailscale" / "c2_code"
    server_binary_path = server_folder_path / "start_server.py"

    parameters = [
        C2ProfileParameter(
            name="callback_interval",
            description="Callback interval in seconds",
            default_value="5",
            verifier_regex=r"^[0-9]+$",
        ),
        C2ProfileParameter(
            name="callback_jitter",
            description="Callback jitter percentage (0-100)",
            default_value="10",
            verifier_regex=r"^[0-9]+$",
        ),
        C2ProfileParameter(
            name="encrypted_exchange_check",
            description="Perform encrypted key exchange",
            default_value="T",
            parameter_type=ParameterType.ChooseOne,
            choices=["T", "F"],
        ),
        C2ProfileParameter(
            name="AESPSK",
            description="Encryption type",
            default_value="aes256_hmac",
            parameter_type=ParameterType.ChooseOne,
            choices=["aes256_hmac", "none"],
            crypto_type=True,
        ),
        C2ProfileParameter(
            name="killdate",
            description="Kill date for the agent",
            default_value=28,
            parameter_type=ParameterType.Date,
        ),
    ]

    custom_rpc_functions = {
        "generate_config": generate_config,
    }
