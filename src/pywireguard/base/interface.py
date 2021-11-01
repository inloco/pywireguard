from abc import ABC, abstractmethod
from typing import List

from .peer import Peer


class Interface(ABC):
    """ A wrapper for a Wireguard interface

    An abstraction to a Wireguard tunnel interface.

    Typical usage example::

        from pywireguard.factory import Interface

        wgtest0 = Interface('wgtest0')
        wgtest0.private_key = generate_private_key()
    """

    @abstractmethod
    def __init__(self, name):
        pass

    @abstractmethod
    def _get_private_key(self) -> bytes:
        pass

    @abstractmethod
    def _set_private_key(self, private_key: bytes) -> None:
        pass

    @abstractmethod
    def _get_listen_port(self) -> int:
        pass

    @abstractmethod
    def _set_listen_port(self, listen_port: int) -> None:
        pass

    @abstractmethod
    def _get_fwmark(self) -> int:
        pass

    @abstractmethod
    def _set_fwmark(self, fwmark: int) -> None:
        pass

    @abstractmethod
    def _get_public_key(self) -> bytes:
        pass

    @abstractmethod
    def _get_peers(self) -> List[Peer]:
        pass

    @abstractmethod
    def _upsert_peer(self, peer: Peer) -> None:
        pass

    @abstractmethod
    def _remove_peer(self, peer: Peer) -> None:
        pass

    @property
    def private_key(self) -> bytes:
        """A base64 private key. Required."""
        return self._get_private_key()

    @private_key.setter
    def private_key(self, private_key: bytes) -> None:
        self._set_private_key(private_key)

    @property
    def listen_port(self) -> int:
        """A integer port for listening. Optional; if not specified, chosen randomly."""
        return self._get_listen_port()

    @listen_port.setter
    def listen_port(self, listen_port: int) -> None:
        self._set_listen_port(listen_port)

    @property
    def fwmark(self) -> int:
        """A 32-bit fwmark for outgoing packets. If set to 0 or "off", this option is disabled. Optional."""
        return self._get_fwmark()

    @fwmark.setter
    def fwmark(self, fwmark: int) -> None:
        self._set_fwmark(fwmark)

    @property
    def peers(self) -> List[Peer]:
        """List of device peers."""
        return self._get_peers()

    @property
    def public_key(self) -> bytes:
        """The base64 representation of a Wireguard public key. It is automatically generated from the private key."""
        return self._get_public_key()

    def upsert_peer(self, peer: Peer) -> None:
        """Add or update peer on interface.

        Args:
            peer: a Peer object.

        Typical usage example::

            from pywireguard.factory import Peer
            ...
            peer = Peer(
                public_key,
                preshared_key=generate_preshared_key()
            )
            wgtest0.upsert_peer(peer)
        """
        self._upsert_peer(peer)

    def remove_peer(self, peer: Peer) -> None:
        """Remove peer from interface.

        Args:
            peer: a Peer object.

        Typical usage example::

            ...
            peer = wgtest0.peers[0]
            wgtest0.remove_peer(peer)
        """
        self._remove_peer(peer)
