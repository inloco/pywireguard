import os.path
from time import sleep

from ..exceptions import BadInterfaceName, RetryAttemptsExceeded
from ..userspace.interface import UserspaceInterface


class WindowsInterface(UserspaceInterface):
    PIPE_PATH = r'\\.\pipe\ProtectedPrefix\Administrators\WireGuard'

    def __init__(self, name):
        self.name = name
        self.pipe = f'{self.PIPE_PATH}\\{self.name}'
        if not os.path.exists(self.pipe):
            raise BadInterfaceName()

    def _pipe_command(self, command) -> str:
        buffer = ''
        error_count = 0
        while error_count < 10:
            try:
                with open(self.pipe, 'rb+', buffering=0) as pipe:
                    pipe.write(command)
                    while '\n\n' not in buffer:
                        buffer += pipe.readline().decode()
                return buffer
            except OSError:
                error_count += 1
                sleep(1)
        raise RetryAttemptsExceeded()

    def _command_get(self) -> str:
        return self._pipe_command(b'get=1\n\n')

    def _command_set(self, command: str) -> None:
        self._pipe_command(f'set=1\n{command}\n\n'.encode())
