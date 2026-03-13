from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


# ---------- whoami ----------

class WhoamiArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class WhoamiCommand(CommandBase):
    cmd = "whoami"
    needs_admin = False
    help_cmd = "whoami"
    description = "Get current user information including UID, GID, groups, and elevation status."
    version = 1
    author = ""
    argument_class = WhoamiArguments
    attackmapping = ["T1033"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- hostname ----------

class HostnameArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class HostnameCommand(CommandBase):
    cmd = "hostname"
    needs_admin = False
    help_cmd = "hostname"
    description = "Get the system hostname."
    version = 1
    author = ""
    argument_class = HostnameArguments
    attackmapping = ["T1082"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- ps ----------

class PsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class PsCommand(CommandBase):
    cmd = "ps"
    needs_admin = False
    help_cmd = "ps"
    description = "List running processes with PID, PPID, user, and command line."
    version = 1
    author = ""
    argument_class = PsArguments
    attackmapping = ["T1057"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- ls ----------

class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="Path",
                display_name="Path",
                type=ParameterType.String,
                default_value=".",
                description="Directory to list (default: current directory).",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            return
        if self.command_line.strip()[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line.strip())


class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls /tmp"
    description = "List directory contents with permissions, size, and modification time."
    version = 1
    author = ""
    argument_class = LsArguments
    attackmapping = ["T1083"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        path = taskData.args.get_arg("path")
        if path:
            response.DisplayParams = path
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- cd ----------

class CdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="Path",
                display_name="Path",
                type=ParameterType.String,
                default_value="~",
                description="Directory to change to.",
                parameter_group_info=[ParameterGroupInfo(required=False)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            return
        if self.command_line.strip()[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line.strip())


class CdCommand(CommandBase):
    cmd = "cd"
    needs_admin = False
    help_cmd = "cd /tmp"
    description = "Change the agent's working directory."
    version = 1
    author = ""
    argument_class = CdArguments
    attackmapping = []
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        response.DisplayParams = taskData.args.get_arg("path") or "~"
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- pwd ----------

class PwdArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class PwdCommand(CommandBase):
    cmd = "pwd"
    needs_admin = False
    help_cmd = "pwd"
    description = "Print the agent's current working directory."
    version = 1
    author = ""
    argument_class = PwdArguments
    attackmapping = []
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- cat ----------

class CatArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="Path",
                display_name="File Path",
                type=ParameterType.String,
                description="File to read.",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        if len(self.command_line.strip()) == 0:
            raise Exception("Must provide a file path.")
        if self.command_line.strip()[0] == "{":
            self.load_args_from_json_string(self.command_line)
        else:
            self.add_arg("path", self.command_line.strip())


class CatCommand(CommandBase):
    cmd = "cat"
    needs_admin = False
    help_cmd = "cat /etc/passwd"
    description = "Read and display file contents (capped at 1MB)."
    version = 1
    author = ""
    argument_class = CatArguments
    attackmapping = ["T1005"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)
        response.DisplayParams = taskData.args.get_arg("path")
        return response

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- ifconfig ----------

class IfconfigArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class IfconfigCommand(CommandBase):
    cmd = "ifconfig"
    needs_admin = False
    help_cmd = "ifconfig"
    description = "List network interfaces with MAC addresses, IPs, and flags."
    version = 1
    author = ""
    argument_class = IfconfigArguments
    attackmapping = ["T1016"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- env ----------

class EnvArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class EnvCommand(CommandBase):
    cmd = "env"
    needs_admin = False
    help_cmd = "env"
    description = "List environment variables."
    version = 1
    author = ""
    argument_class = EnvArguments
    attackmapping = ["T1082"]
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)


# ---------- exit ----------

class ExitArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = []

    async def parse_arguments(self):
        pass


class ExitCommand(CommandBase):
    cmd = "exit"
    needs_admin = False
    help_cmd = "exit"
    description = "Terminate the agent process."
    version = 1
    author = ""
    argument_class = ExitArguments
    attackmapping = []
    attributes = CommandAttributes(dependencies=[])

    async def create_go_tasking(self, taskData: PTTaskMessageAllData) -> PTTaskCreateTaskingMessageResponse:
        return PTTaskCreateTaskingMessageResponse(TaskID=taskData.Task.ID, Success=True)

    async def process_response(self, task: PTTaskMessageAllData, response: any) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
