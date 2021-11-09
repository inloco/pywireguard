from abc import ABC, abstractmethod
from functools import total_ordering
from typing import List


@total_ordering
class Peer(ABC):
    """
    Class representing peer information.

    Attributes
    ----------
    public_key : bytes
        The base64 representation of a WireGuard public key for this peer. (read-only)
    preshared_key : bytes
        The base64 representation of a WireGuard preshared key for this peer.
    endpoint : str
        An endpoint IP followed by a colon, and then a port number.
    allowed_ips : List[str]
        The list of peer allowed IPs.
    persistent_keepalive_interval: int
        The value for this is a integer corresponding to the persistent keepalive interval of the
        peer. The value 0 disables it.
    rx_bytes : int
        The number of received bytes for the peer. (read-only)
    tx_bytes : int
        The number of transmitted bytes for the peer. (read-only)
    last_handshake_time_sec : int
        The number of seconds of the most recent handshake for the peer. (read-only)
    last_handshake_time_nsec : int
        The number of nano-seconds of the most recent handshake for the peer. (read-only)
    """

    def __init__(self, public_key: bytes, preshared_key: bytes = None, endpoint: str = None,
                 allowed_ips: List[str] = None, persistent_keepalive_interval: int = None,
                 rx_bytes: int = None, tx_bytes: int = None, last_handshake_time_sec: int = None,
                 last_handshake_time_nsec: int = None):
        self._public_key = public_key
        self.preshared_key = preshared_key
        self.endpoint = endpoint
        self.allowed_ips = allowed_ips
        self.persistent_keepalive_interval = persistent_keepalive_interval
        self.rx_bytes = rx_bytes
        self.tx_bytes = tx_bytes
        self.last_handshake_time_sec = last_handshake_time_sec
        self.last_handshake_time_nsec = last_handshake_time_nsec

    @property
    def public_key(self) -> bytes:
        return self._public_key

    @abstractmethod
    def serialize(self):
        pass

    def __eq__(self, other):
        return self.public_key == other.public_key

    def __lt__(self, other):
        return self.public_key < other.public_key
