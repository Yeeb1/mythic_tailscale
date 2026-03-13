from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class ShellArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="command",
                cli_name="Command",
                display_name="Command",
                type=ParameterType.String,
                description="Command to execute via shell.",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line) == 0:
            raise Exception("Must provide a command to run.")
        if self.command_line.strip()[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("command", self.command_line)


class ShellCommand(CommandBase):
    cmd = "shell"
    needs_admin = False
    help_cmd = "shell whoami"
    description = "Execute a command via the OS shell (cmd.exe on Windows, /bin/sh on Linux/macOS)."
    version = 1
    author = ""
    argument_class = ShellArguments
    attackmapping = ["T1059"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        response.DisplayParams = taskData.args.get_arg("command")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
