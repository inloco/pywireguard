from typing import List

from pr2modules.netlink import NetlinkError
from pr2modules.netlink.generic.wireguard import WireGuard

from .peer import LinuxPeer
from ..exceptions import BadInterfaceName
from ..interface import Interface
from ..peer import Peer


class LinuxInterface(Interface):

    def __init__(self, name):
        self._wg = WireGuard()
        try:
            self._wg.info(name)
        except NetlinkError as e:
            raise BadInterfaceName(e)
        self.name = name

    @staticmethod
    def _get_attribute(data, name):
        return dict(
            dict(data)['attrs']
        ).get(name)

    def _get_interface_attribute(self, name):
        return self._get_attribute(
            self._wg.info(self.name)[0],
            name
        )

    def _get_private_key(self) -> bytes:
        return self._get_interface_attribute('WGDEVICE_A_PRIVATE_KEY')

    def _set_private_key(self, private_key: bytes) -> None:
        self._wg.set(self.name, private_key=private_key)

    def _get_listen_port(self) -> int:
        return self._get_interface_attribute('WGDEVICE_A_LISTEN_PORT')

    def _set_listen_port(self, listen_port: int) -> None:
        self._wg.set(self.name, listen_port=listen_port)

    def _get_fwmark(self) -> int:
        return self._get_interface_attribute('WGDEVICE_A_FWMARK')

    def _set_fwmark(self, fwmark: int) -> None:
        self._wg.set(self.name, fwmark=fwmark)

    def _get_peers(self) -> List[Peer]:
        result = list()
        peers = self._get_interface_attribute('WGDEVICE_A_PEERS')
        if peers is not None:
            for peer in peers:
                endpoint_data = self._get_attribute(peer, 'WGPEER_A_ENDPOINT')
                allowed_ips_data = self._get_attribute(peer, 'WGPEER_A_ALLOWEDIPS')
                allowed_ips = [allowed_ip['addr'] for allowed_ip in allowed_ips_data] \
                    if allowed_ips_data is not None else list()
                endpoint = f"{endpoint_data['addr']}:{endpoint_data['port']}" if endpoint_data is not None else None

                n_peer = LinuxPeer(
                    public_key=self._get_attribute(peer, 'WGPEER_A_PUBLIC_KEY'),
                    preshared_key=self._get_attribute(peer, 'WGPEER_A_PRESHARED_KEY'),
                    last_handshake_time_sec=self._get_attribute(peer, 'WGPEER_A_LAST_HANDSHAKE_TIME')['tv_sec'],
                    last_handshake_time_nsec=self._get_attribute(peer, 'WGPEER_A_LAST_HANDSHAKE_TIME')['tv_nsec'],
                    rx_bytes=self._get_attribute(peer, 'WGPEER_A_RX_BYTES'),
                    tx_bytes=self._get_attribute(peer, 'WGPEER_A_TX_BYTES'),
                    endpoint=endpoint,
                    allowed_ips=allowed_ips,
                    persistent_keepalive_interval=self._get_attribute(peer, 'WGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL')
                )
                result.append(n_peer)
        return result

    def _upsert_peer(self, peer: Peer) -> None:
        self._wg.set(self.name, peer=peer.serialize())

    def _remove_peer(self, peer: Peer) -> None:
        peer_to_remove = dict(
            public_key=peer.public_key,
            remove=True
        )
        self._wg.set(self.name, peer=peer_to_remove)

    def _get_public_key(self) -> bytes:
        return self._get_interface_attribute('WGDEVICE_A_PUBLIC_KEY')
