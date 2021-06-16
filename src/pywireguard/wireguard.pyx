cimport cwireguard
from cpython.mem cimport PyMem_Malloc, PyMem_Free
import socket
import logging


def allowed_ip_to_list(allowed_ip: AllowedIP):
    if allowed_ip is None:
        return list()
    else:
        return [allowed_ip] + allowed_ip_to_list(allowed_ip.get_next_ip())

def peers_to_list(peer: Peer):
    if peer is None:
        return list()
    else:
        return [peer] + peers_to_list(peer.get_next_peer())

def generate_keys():
    """Generates wireguard random keys.

    Returns:
        A dict containing a private key, its corresponding public key and a pre-shared key.

    Return example:

    .. code-block:: python

        {
            'private_key': b'CBHLv4rj20nG9BX2cl9SfMzd3Q7fjC0yHklan1Mnuk0=',
            'public_key': b'LpWmEA1r5lFYZNeQtQSkTtaHBKvHYQyMKXGUGIc2AC4=',
            'preshared_key': b'AWlk9L1O7v1MHiqt+zck1Gyxo9Zxl3EBU4EqM3DZcEE='
        }
    """
    cdef cwireguard.wg_key private_key, public_key, preshared_key
    cdef cwireguard.wg_key_b64_string b64_private_key, b64_public_key, b64_preshared_key

    cwireguard.wg_generate_private_key(private_key)
    cwireguard.wg_key_to_base64(b64_private_key, private_key)

    cwireguard.wg_generate_public_key(public_key, private_key)
    cwireguard.wg_key_to_base64(b64_public_key, public_key)

    cwireguard.wg_generate_preshared_key(preshared_key)
    cwireguard.wg_key_to_base64(b64_preshared_key, preshared_key)

    return dict(
        private_key=b64_private_key,
        public_key=b64_public_key,
        preshared_key=b64_preshared_key
    )


class InvalidOperationException(Exception):
    """Signals that it was not possible to perform the requested operation."""
    pass


cdef class AllowedIP:
    """ A wrapper for a Wireguard allowed IP

    An IPv4 addresses with CIDR masks from which incoming traffic for a peer is allowed
    and to which outgoing traffic for this peer is directed. The catch-all 0.0.0.0/0 may be
    specified for matching all IPv4 addresses.

    Typical usage example::

        allowed_ip = AllowedIP(
            ip='10.18.0.1',
            cidr=32
        )
    """
    cdef cwireguard.wg_allowedip* _allowedip
    cdef AllowedIP _next_allowedip

    def __cinit__(
        self, peer: Peer = None, parent_ip: AllowedIP = None,
        ip: str = None, cidr: int = None
    ):
        if peer is not None:
            self._allowedip = peer._peer.first_allowedip
            if self._allowedip.next_allowedip is not NULL:
                self._next_allowedip = AllowedIP(parent_ip=self)
        elif parent_ip is not None:
            self._allowedip = parent_ip._allowedip.next_allowedip
            if self._allowedip.next_allowedip is not NULL:
                self._next_allowedip = AllowedIP(parent_ip=self)
        else:
            self._allowedip = <cwireguard.wg_allowedip*> PyMem_Malloc(sizeof(cwireguard.wg_allowedip))
            if self._allowedip is NULL:
                raise MemoryError()
            self._allowedip.next_allowedip = NULL
        
        if ip is not None:
            self.ip = ip
        if cidr is not None:
            self.cidr = cidr

    def __dealloc__(self):
        PyMem_Free(self._allowedip)

    def __repr__(self):
        return f"{self.ip}/{self.cidr}"

    def get_next_ip(self) -> AllowedIP:
        return self._next_allowedip

    @property
    def cidr(self):
        """An integet IPv4 CIDR mask"""
        return self._allowedip.cidr
    
    @cidr.setter
    def cidr(self, value: int):
        self._allowedip.cidr = value

    @property
    def ip(self):
        """The string representation of an IPv4 address"""
        return socket.inet_ntoa(self._allowedip.ip4.s_addr.to_bytes(4, 'little'))

    @ip.setter
    def ip(self, string):
        ip_bytes = socket.inet_aton(string)
        self._allowedip.family = 0x02
        self._allowedip.ip4.s_addr = int.from_bytes(ip_bytes, byteorder='little', signed=False)


cdef class Device:
    """ A wrapper for a Wireguard device

    An abstraction to a Wireguard tunnel interface.

    Typical usage example::

        wg0 = Device('wg0') # Read device data or creates a new one
        peer = Peer(
            public_key=b'GNfYWhcvNeCfUkcIsCg108Y1vRNpK7eQuxE+42EeTAE='
        )
        wg0.add_peer(peer)
        wg0.update()
    """
    cdef cwireguard.wg_device* _device
    cdef Peer _first_peer
    cdef str device_name

    def __cinit__(self, device_name):
        self._device = <cwireguard.wg_device*> PyMem_Malloc(sizeof(cwireguard.wg_device))
        self._first_peer = None
        self._device.flags = <cwireguard.wg_device_flags> 0x00
        if cwireguard.wg_add_device(device_name.encode()) < 0:
            logging.info("Using existing device.")
        self.device_name = device_name
        self.reload()

    def get_peers(self):
        """Get the list of device peers."""
        return peers_to_list(self._first_peer)

    def clear_peers(self):
        """Remove all Peers."""
        self._first_peer = None
        self._device.first_peer = NULL
        self._device.last_peer = NULL
        self.replace_peers = True
        self.update()

    def update(self):
        """Save the device state."""
        if cwireguard.wg_set_device(self._device) < 0:
            raise InvalidOperationException("Unable to set device")
        self.reload()

    def reload(self):
        """Reload device information from Wireguard."""
        if cwireguard.wg_get_device(&self._device, self.device_name.encode()) < 0:
            raise InvalidOperationException("Unable to get device")

        if self._device.first_peer is not NULL:
            self._first_peer = Peer(self)

    @classmethod
    def list(cls):
        """Lista all Wireguard devices."""
        return cwireguard.wg_list_device_names_fixed().decode().split('\n')

    def add_peer(self, peer: Peer):
        """Adds a new peer to device.

        Args:
            peer: a Peer object.
        
        Typical usage example::

            wg0 = Device('wg0')
            peer = Peer()
            ...
            wg0.add_peer(peer)
        """
        peer._peer.next_peer = self._device.first_peer
        self._device.first_peer = peer._peer
        if self._device.last_peer == NULL:
            self._device.last_peer = peer._peer
        
        self.update()

    @property
    def private_key(self):
        """The base64 representation of a Wireguard private key. Requires an update."""
        cdef cwireguard.wg_key_b64_string b64_key
        cwireguard.wg_key_to_base64(b64_key, self._device.private_key)
        return b64_key

    @private_key.setter
    def private_key(self, b64_key: bytes):
        self.has_private_key = True
        cwireguard.wg_key_from_base64(self._device.private_key, b64_key)

    @property
    def public_key(self):
        """The base64 representation of a Wireguard public key. Is generated from private key after an update."""
        cdef cwireguard.wg_key_b64_string b64_key
        cwireguard.wg_key_to_base64(b64_key, self._device.public_key)
        return b64_key

    @property
    def name(self):
        """The Wireguard device name."""
        return self._device.name.decode()

    @property
    def listen_port(self):
        """The device listen port."""
        return self._device.listen_port

    @listen_port.setter
    def listen_port(self, value: int):
        self._device.listen_port = value
        self.has_listen_port = True

    def delete(self):
        """Deletes the current device."""
        if cwireguard.wg_del_device(self._device.name) < 0:
            raise InvalidOperationException("Unable to delete device")

    def __dealloc__(self):
        PyMem_Free(self._device)

    ######### FLAGS ###########
    @property
    def replace_peers(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._device.flags & cwireguard.wg_device_flags.WGDEVICE_REPLACE_PEERS > 0

    @replace_peers.setter
    def replace_peers(self, value: bool):
        self._device.flags = <cwireguard.wg_device_flags> (
            (self._device.flags | cwireguard.wg_device_flags.WGDEVICE_REPLACE_PEERS) if value
             else (self._device.flags & ~cwireguard.wg_device_flags.WGDEVICE_REPLACE_PEERS)
        )

    @property
    def has_private_key(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._device.flags & cwireguard.wg_device_flags.WGDEVICE_HAS_PRIVATE_KEY > 0

    @has_private_key.setter
    def has_private_key(self, value: bool):
        self._device.flags = <cwireguard.wg_device_flags> (
            (self._device.flags | cwireguard.wg_device_flags.WGDEVICE_HAS_PRIVATE_KEY) if value
             else (self._device.flags & ~cwireguard.wg_device_flags.WGDEVICE_HAS_PRIVATE_KEY)
        )

    @property
    def has_public_key(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._device.flags & cwireguard.wg_device_flags.WGDEVICE_HAS_PUBLIC_KEY > 0

    @has_public_key.setter
    def has_public_key(self, value: bool):
        self._device.flags = <cwireguard.wg_device_flags> (
            (self._device.flags | cwireguard.wg_device_flags.WGDEVICE_HAS_PUBLIC_KEY) if value
             else (self._device.flags & ~cwireguard.wg_device_flags.WGDEVICE_HAS_PUBLIC_KEY)
        )

    @property
    def has_listen_port(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._device.flags & cwireguard.wg_device_flags.WGDEVICE_HAS_LISTEN_PORT > 0

    @has_listen_port.setter
    def has_listen_port(self, value: bool):
        self._device.flags = <cwireguard.wg_device_flags> (
            (self._device.flags | cwireguard.wg_device_flags.WGDEVICE_HAS_LISTEN_PORT) if value
             else (self._device.flags & ~cwireguard.wg_device_flags.WGDEVICE_HAS_LISTEN_PORT)
        )

    @property
    def has_fwmark(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._device.flags & cwireguard.wg_device_flags.WGDEVICE_HAS_FWMARK > 0

    @has_fwmark.setter
    def has_fwmark(self, value: bool):
        self._device.flags = <cwireguard.wg_device_flags> (
            (self._device.flags | cwireguard.wg_device_flags.WGDEVICE_HAS_FWMARK) if value
             else (self._device.flags & ~cwireguard.wg_device_flags.WGDEVICE_HAS_FWMARK)
        )


cdef class Peer:
    """ A wrapper for a Wireguard Peer

    An abstraction to a Wireguard peer.

    Typical usage example::

        wg0 = Device('wg0')
        peer = Peer(
            public_key=b'GNfYWhcvNeCfUkcIsCg108Y1vRNpK7eQuxE+42EeTAE='
        )
        wg0.add_peer(peer)
        wg0.update()
    """
    cdef cwireguard.wg_peer* _peer
    cdef Peer next_peer
    cdef AllowedIP _first_allowedip

    def __cinit__(
        self, device: Device = None, parent_peer: Peer = None,
        public_key: bytes = None, preshared_key: bytes = None
    ):

        if device is not None:
            self._peer = device._device.first_peer
            if self._peer.next_peer is not NULL:
                self.next_peer = Peer(parent_peer=self)
        elif parent_peer is not None:
            self._peer = parent_peer._peer.next_peer
            if self._peer.next_peer is not NULL:
                self.next_peer = Peer(parent_peer=self)
        else:
            self._peer = <cwireguard.wg_peer*> PyMem_Malloc(sizeof(cwireguard.wg_peer))
            if self._peer is NULL:
                raise MemoryError()
            self._peer.next_peer = NULL
            self._peer.first_allowedip = NULL
            self._peer.last_allowedip = NULL

        self._peer.flags = <cwireguard.wg_peer_flags> 0x00
        if self._peer.first_allowedip is not NULL:
            self._first_allowedip = AllowedIP(self)
        else:
            self._first_allowedip = None

        if public_key is not None:
            self.public_key = public_key
        if preshared_key is not None:
            self.preshared_key = preshared_key

    def __dealloc__(self):
        PyMem_Free(self._peer)

    def get_allowed_ips(self):
        """Get the list of peer allowed IPs."""
        return allowed_ip_to_list(self._first_allowedip)

    def clear_allowed_ips(self):
        """Remove all allowed IPs"""
        self._peer.first_allowedip = NULL
        self._peer.last_allowedip = NULL
        self.replace_allowedips = True

    def add_allowed_ip(self, allowed_ip: AllowedIP):
        """Adds a new allowed IP to device.

        Args:
            allowed_ip: an AllowedIP object.
        
        Typical usage example::

            wg0 = Device('wg0')
            peer = Peer()
            allowed_ip = AllowedIP()
            allowed_ip.ip = '10.18.0.0'
            allowed_ip.cidr = 16
            peer.add_allowed_ip(allowed_ip)
            wg0.add_peer(peer)
            wg0.update()
        """
        allowed_ip._allowedip.next_allowedip = self._peer.first_allowedip
        self._peer.first_allowedip = allowed_ip._allowedip
        if self._peer.last_allowedip == NULL:
            self._peer.last_allowedip = allowed_ip._allowedip
        self._first_allowedip = AllowedIP(self)

    def get_next_peer(self) -> Peer:
        return self.next_peer

    @property
    def public_key(self):
        """The base64 representation of a Wireguard public key for this peer."""
        cdef cwireguard.wg_key_b64_string b64_key
        cwireguard.wg_key_to_base64(b64_key, self._peer.public_key)
        return b64_key

    @public_key.setter
    def public_key(self, bytes b64_key):
        self.has_public_key = True
        cwireguard.wg_key_from_base64(self._peer.public_key, b64_key)


    @property
    def preshared_key(self):
        """The base64 representation of a Wireguard preshared key for this peer."""
        cdef cwireguard.wg_key_b64_string b64_key
        cwireguard.wg_key_to_base64(b64_key, self._peer.preshared_key)
        return b64_key

    @preshared_key.setter
    def preshared_key(self, bytes b64_key):
        self.has_preshared_key = True
        cwireguard.wg_key_from_base64(self._peer.preshared_key, b64_key)

    ######### FLAGS ###########
    @property
    def remove_me(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._peer.flags & cwireguard.wg_peer_flags.WGPEER_REMOVE_ME > 0

    @remove_me.setter
    def remove_me(self, value: bool):
        self._peer.flags = <cwireguard.wg_peer_flags> (
            (self._peer.flags | cwireguard.wg_peer_flags.WGPEER_REMOVE_ME) if value
             else (self._peer.flags & ~cwireguard.wg_peer_flags.WGPEER_REMOVE_ME)
        )

    @property
    def replace_allowedips(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._peer.flags & cwireguard.wg_peer_flags.WGPEER_REPLACE_ALLOWEDIPS > 0

    @replace_allowedips.setter
    def replace_allowedips(self, value: bool):
        self._peer.flags = <cwireguard.wg_peer_flags> (
            (self._peer.flags | cwireguard.wg_peer_flags.WGPEER_REPLACE_ALLOWEDIPS) if value
             else (self._peer.flags & ~cwireguard.wg_peer_flags.WGPEER_REPLACE_ALLOWEDIPS)
        )

    @property
    def has_public_key(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._peer.flags & cwireguard.wg_peer_flags.WGPEER_HAS_PUBLIC_KEY > 0

    @has_public_key.setter
    def has_public_key(self, value: bool):
        self._peer.flags = <cwireguard.wg_peer_flags> (
            (self._peer.flags | cwireguard.wg_peer_flags.WGPEER_HAS_PUBLIC_KEY) if value
             else (self._peer.flags & ~cwireguard.wg_peer_flags.WGPEER_HAS_PUBLIC_KEY)
        )

    @property
    def has_preshared_key(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._peer.flags & cwireguard.wg_peer_flags.WGPEER_HAS_PRESHARED_KEY > 0

    @has_preshared_key.setter
    def has_preshared_key(self, value: bool):
        self._peer.flags = <cwireguard.wg_peer_flags> (
            (self._peer.flags | cwireguard.wg_peer_flags.WGPEER_HAS_PRESHARED_KEY) if value
             else (self._peer.flags & ~cwireguard.wg_peer_flags.WGPEER_HAS_PRESHARED_KEY)
        )

    @property
    def has_persistent_keepalive_interval(self) -> bool:
        """Flag used to mark what changes in an update."""
        return self._peer.flags & cwireguard.wg_peer_flags.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL > 0

    @has_persistent_keepalive_interval.setter
    def has_persistent_keepalive_interval(self, value: bool):
        self._peer.flags = <cwireguard.wg_peer_flags> (
            (self._peer.flags | cwireguard.wg_peer_flags.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL) if value
             else (self._peer.flags & ~cwireguard.wg_peer_flags.WGPEER_HAS_PERSISTENT_KEEPALIVE_INTERVAL)
        )
