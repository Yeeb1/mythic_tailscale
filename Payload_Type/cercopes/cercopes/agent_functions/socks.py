import json
from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="port",
                cli_name="Port",
                display_name="Port",
                type=ParameterType.Number,
                description="Port for the SOCKS5 proxy.",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=0,
                    required=True,
                )],
            ),
            CommandParameter(
                name="action",
                cli_name="Action",
                display_name="Action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop"],
                default_value="start",
                description="Start or stop the SOCKS5 proxy.",
                parameter_group_info=[ParameterGroupInfo(
                    ui_position=1,
                    required=False,
                )],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide a port number.")
        try:
            self.load_args_from_json_string(self.command_line)
        except Exception:
            port = self.command_line.strip()
            try:
                self.add_arg("port", int(port))
            except ValueError:
                raise Exception(f"Invalid port: {port}")


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks -Port 1080 -Action start"
    description = "Start/stop a SOCKS5 proxy through the agent. Traffic is routed over the Tailscale mesh."
    version = 1
    script_only = True
    author = "@Yeeb1"
    argument_class = SocksArguments
    attackmapping = ["T1090"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port")
        response.DisplayParams = f"-Action {action} -Port {port}"

        if action == "start":
            resp = await SendMythicRPCProxyStartCommand(MythicRPCProxyStartMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                LocalPort=port,
            ))
            if not resp.Success:
                response.TaskStatus = MythicStatus.Error
                response.Stderr = resp.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=resp.Error.encode(),
                ))
            else:
                response.TaskStatus = MythicStatus.Success
                response.Completed = True
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"Started SOCKS5 proxy on port {port}\nSetting sleep to 0 for low latency".encode(),
                ))
                # Set sleep to 0 for real-time SOCKS proxying
                await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
                    TaskID=taskData.Task.ID,
                    CommandName="sleep",
                    Params=json.dumps({"interval": 0}),
                ))
        else:
            resp = await SendMythicRPCProxyStopCommand(MythicRPCProxyStopMessage(
                TaskID=taskData.Task.ID,
                PortType="socks",
                Port=port,
            ))
            if not resp.Success:
                response.TaskStatus = MythicStatus.Error
                response.Stderr = resp.Error
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=resp.Error.encode(),
                ))
            else:
                response.TaskStatus = MythicStatus.Success
                response.Completed = True
                await SendMythicRPCResponseCreate(MythicRPCResponseCreateMessage(
                    TaskID=taskData.Task.ID,
                    Response=f"Stopped SOCKS5 proxy on port {port}\nRestoring sleep to 5s".encode(),
                ))
                await SendMythicRPCTaskCreateSubtask(MythicRPCTaskCreateSubtaskMessage(
                    TaskID=taskData.Task.ID,
                    CommandName="sleep",
                    Params=json.dumps({"interval": 5}),
                ))

        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
