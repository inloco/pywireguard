import os
from subprocess import getstatusoutput, check_call
from tempfile import NamedTemporaryFile
from typing import List

from .peer import CLIPeer
from ..exceptions import BadInterfaceName
from ..interface import Interface
from ..peer import Peer


class CLIInterface(Interface):
    def __init__(self, name):
        status, _ = getstatusoutput(f"wg show {name}")
        if status != 0:
            raise BadInterfaceName()
        self.name = name

    def _get_private_key(self) -> bytes:
        status, output = getstatusoutput(f"wg show {self.name} private-key")
        if status != 0:
            raise BadInterfaceName()
        return output.strip().encode()

    def _set_private_key(self, private_key: bytes) -> None:
        with NamedTemporaryFile(delete=False) as file:
            file.write(private_key)
            filename = file.name
        status, _ = getstatusoutput(f"wg set {self.name} private-key {filename}")
        os.remove(filename)
        if status != 0:
            raise BadInterfaceName()

    def _get_listen_port(self) -> int:
        status, output = getstatusoutput(f"wg show {self.name} listen-port")
        if status != 0:
            raise BadInterfaceName()
        return int(output.strip())

    def _set_listen_port(self, listen_port: int) -> None:
        status, _ = getstatusoutput(f"wg set {self.name} listen-port {listen_port}")
        if status != 0:
            raise BadInterfaceName()

    def _get_fwmark(self) -> int:
        status, output = getstatusoutput(f"wg show {self.name} fwmark")
        if status != 0:
            raise BadInterfaceName()
        try:
            fwmark = int(output.strip(), 0)
        except ValueError:
            fwmark = 0
        return fwmark

    def _set_fwmark(self, fwmark: int) -> None:
        status, _ = getstatusoutput(f"wg set {self.name} fwmark {fwmark}")
        if status != 0:
            raise BadInterfaceName()

    def _get_public_key(self) -> bytes:
        status, output = getstatusoutput(f"wg show {self.name} public-key")
        if status != 0:
            raise BadInterfaceName()
        return output.strip().encode()

    def _get_peers(self) -> List[Peer]:
        peers = dict()

        _, preshared_keys = getstatusoutput(f"wg show {self.name} preshared-keys")
        for key in preshared_keys.split('\n'):
            peer_id, psk = key.strip().split('\t')
            peers[peer_id] = dict(public_key=peer_id.encode(), preshared_key=psk.encode())

        _, endpoints = getstatusoutput(f"wg show {self.name} endpoints")
        for key in endpoints.split('\n'):
            peer_id, endpoint = key.strip().split('\t')
            peers[peer_id]['endpoint'] = endpoint

        _, allowed_ips = getstatusoutput(f"wg show {self.name} allowed-ips")
        for key in allowed_ips.split('\n'):
            peer_id, p_allowed_ips = key.strip().split('\t')
            peers[peer_id]['allowed_ips'] = p_allowed_ips.split(' ')

        _, p_persistent_keepalive = getstatusoutput(f"wg show {self.name} persistent-keepalive")
        for key in p_persistent_keepalive.split('\n'):
            peer_id, persistent_keepalive = key.strip().split('\t')
            try:
                persistent_keepalive = int(persistent_keepalive)
            except ValueError:
                persistent_keepalive = 0
            peers[peer_id]['persistent_keepalive_interval'] = persistent_keepalive

        _, transfers = getstatusoutput(f"wg show {self.name} transfer")
        for key in transfers.split('\n'):
            peer_id, transfer = key.strip().split('\t', maxsplit=1)
            tx, rx = transfer.split('\t')
            peers[peer_id]['tx_bytes'] = int(tx)
            peers[peer_id]['rx_bytes'] = int(rx)

        return [CLIPeer(**peers[peer_id]) for peer_id in peers.keys()]

    def _upsert_peer(self, peer: Peer) -> None:
        peer_id = peer.public_key.decode()
        check_call(f"wg set {self.name} peer {peer_id}", shell=True)

        with NamedTemporaryFile(delete=False) as file:
            file.write(peer.preshared_key)
            filename = file.name
        check_call(f"wg set {self.name} peer {peer_id} preshared-key {filename}", shell=True)
        os.remove(filename)

        check_call(f"wg set {self.name} peer {peer_id} endpoint {peer.endpoint}", shell=True)
        check_call(f"wg set {self.name} peer {peer_id} allowed-ips {','.join(peer.allowed_ips)}", shell=True)
        getstatusoutput(f"wg set {self.name} peer {peer_id} persistent-keepalive {peer.persistent_keepalive_interval}")

    def _remove_peer(self, peer: Peer) -> None:
        peer_id = peer.public_key.decode()
        check_call(f"wg set {self.name} peer {peer_id} remove", shell=True)
