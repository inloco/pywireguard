import re
from abc import ABC, abstractmethod
from base64 import b64encode, b64decode
from typing import List

from .peer import UserspacePeer
from ..interface import Interface
from ..utils import generate_public_key

# the regular expressions below parser the protocol described at https://www.wireguard.com/xplatform/
_re_private_key = re.compile(r"private_key=([a-f0-9]{64})")
_re_listen_port = re.compile(r"listen_port=([0-9]+)")
_re_fwmark = re.compile(r"fwmark=([0-9]+)")
_re_peer = re.compile(r"(public_key=[^;]*?)(?=public_key|errno|private_key|listen_port|fwmark)", re.M)

_re_peer_public_key = re.compile(r"public_key=([a-f0-9]{64})")
_re_peer_attrs = dict(
    endpoint=re.compile(r"endpoint=(.+)"),
    preshared_key=re.compile(r"preshared_key=([a-f0-9]{64})"),
    persistent_keepalive_interval=re.compile(r"persistent_keepalive_interval=([0-9]+)"),
    allowed_ips=re.compile(r"allowed_ip=(.+)"),
    rx_bytes=re.compile(r"rx_bytes=([0-9]+)"),
    tx_bytes=re.compile(r"tx_bytes=([0-9]+)"),
    last_handshake_time_sec=re.compile(r"last_handshake_time_sec=([0-9]+)"),
    last_handshake_time_nsec=re.compile(r"last_handshake_time_nsec=([0-9]+)")
)


class UserspaceInterface(Interface, ABC):

    @abstractmethod
    def _command_get(self) -> str:
        pass

    @abstractmethod
    def _command_set(self, command: str):
        pass

    @staticmethod
    def _create_peer_from_data(data: str) -> UserspacePeer:
        public_key = b64encode(bytes.fromhex(_re_peer_public_key.findall(data)[0]))
        peer = UserspacePeer(public_key)
        for attr, regex in _re_peer_attrs.items():
            re_result = regex.findall(data)
            print(attr, re_result)
            if len(re_result) > 0:
                value = re_result[0]
                if attr == 'preshared_key':
                    value = b64encode(bytes.fromhex(value))
                if attr == 'allowed_ips':
                    value = re_result
                if attr in ['persistent_keepalive_interval', 'rx_bytes', 'tx_bytes',
                            'last_handshake_time_sec', 'last_handshake_time_nsec']:
                    value = int(value)
                setattr(peer, attr, value)
        return peer

    def _get_data_as_dict(self) -> dict:
        data = self._command_get()
        private_key = _re_private_key.findall(data)
        if len(private_key) > 0:
            private_key = b64encode(bytes.fromhex(private_key[0]))

        listen_port = _re_listen_port.findall(data)
        if len(listen_port) > 0:
            listen_port = int(listen_port[0])

        fwmark = _re_fwmark.findall(data)
        if len(fwmark) > 0:
            fwmark = int(fwmark[0])

        peers = [self._create_peer_from_data(peer) for peer in _re_peer.findall(data)]

        return dict(
            private_key=private_key,
            listen_port=listen_port,
            fwmark=fwmark,
            peers=peers
        )

    def _get_private_key(self) -> bytes:
        data = self._get_data_as_dict()
        return data['private_key']

    def _set_private_key(self, private_key: bytes) -> None:
        hex_private_key = b64decode(private_key).hex()
        self._command_set(f"private_key={hex_private_key}")

    def _get_listen_port(self) -> int:
        data = self._get_data_as_dict()
        return data['listen_port']

    def _set_listen_port(self, listen_port: int) -> None:
        self._command_set(f"listen_port={listen_port}")

    def _get_fwmark(self) -> int:
        data = self._get_data_as_dict()
        return data['fwmark']

    def _set_fwmark(self, fwmark: int) -> None:
        self._command_set(f"fwmark={fwmark}")

    def _get_public_key(self) -> bytes:
        return generate_public_key(self.private_key)

    def _get_peers(self) -> List[UserspacePeer]:
        return self._get_data_as_dict()['peers']

    def _upsert_peer(self, peer: UserspacePeer) -> None:
        self._command_set(peer.serialize())

    def _remove_peer(self, peer: UserspacePeer) -> None:
        hex_public_key = b64decode(peer.public_key).hex()
        command = f"public_key={hex_public_key}\nremove=true"
        self._command_set(command)
