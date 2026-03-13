from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SleepArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="interval",
                cli_name="Interval",
                display_name="Interval (seconds)",
                type=ParameterType.Number,
                description="Callback interval in seconds.",
                parameter_group_info=[ParameterGroupInfo(required=True, ui_position=0)],
            ),
            CommandParameter(
                name="jitter",
                cli_name="Jitter",
                display_name="Jitter (%)",
                type=ParameterType.Number,
                default_value=0,
                description="Jitter percentage (0-100).",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=1)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide an interval.")
        try:
            self.load_args_from_json_string(self.command_line)
        except Exception:
            parts = self.command_line.strip().split()
            self.add_arg("interval", int(parts[0]))
            if len(parts) > 1:
                self.add_arg("jitter", int(parts[1]))


class SleepCommand(CommandBase):
    cmd = "sleep"
    needs_admin = False
    help_cmd = "sleep 5 10"
    description = "Set the callback interval (seconds) and optional jitter percentage."
    version = 1
    author = ""
    argument_class = SleepArguments
    attackmapping = []
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        interval = taskData.args.get_arg("interval")
        jitter = taskData.args.get_arg("jitter") or 0
        response.DisplayParams = f"{interval}s / {jitter}%"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
