import os.path
import socket

from ..exceptions import BadInterfaceName
from ..userspace.interface import UserspaceInterface


class DarwinInterface(UserspaceInterface):
    SOCKET_PATH = '/var/run/wireguard/'

    def __init__(self, name):
        self.name = name
        self.file_socket_name = f'{self.SOCKET_PATH}{self.name}.name'
        if not os.path.exists(self.file_socket_name):
            raise BadInterfaceName()

    def _get_socket(self) -> socket.socket:
        with open(self.file_socket_name) as file:
            socket_name = file.read()
        socket_address = f'{self.SOCKET_PATH}{socket_name.strip()}.sock'
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(socket_address)
        return sock

    def _command_get(self) -> str:
        buffer = ''
        sock = self._get_socket()
        sock.sendall(b'get=1\n\n')
        while '\n\n' not in buffer:
            buffer += sock.recv(1024).decode()
        sock.close()
        return buffer

    def _command_set(self, command: str):
        buffer = ''
        sock = self._get_socket()
        final_cmd = f'set=1\n{command}\n\n'
        print(final_cmd)
        sock.sendall(final_cmd.encode())
        while '\n\n' not in buffer:
            buffer += sock.recv(1024).decode()
        sock.close()
