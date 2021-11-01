from base64 import b64encode, b64decode
from os import urandom

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _clamp_key(random_bytes: bytes):
    z = bytearray(random_bytes)
    z[31] = (z[31] & 0x7f) | 0x40
    z[0] &= 0xf8
    return z


def generate_preshared_key():
    """Generates WireGuard preshared keys.

    Returns:
        A bytes object.

    Typical usage example::

        from pywireguard.base.util import generate_preshared_key
        ...
        peer = Peer(
            public_key,
            preshared_key=generate_preshared_key()
        )
    """
    return b64encode(urandom(32))


def generate_private_key():
    """Generates WireGuard private keys.

    Returns:
        A bytes object.

    Typical usage example::

        from pywireguard.base.util import generate_private_key
        ...
        wgtest0 = Interface('wgtest0')
        wgtest0.private_key = generate_private_key()
    """
    return b64encode(_clamp_key(urandom(32)))

    # Alternative
    # b64encode(x25519.X25519PrivateKey.generate().private_bytes(
    #     encoding=serialization.Encoding.Raw,
    #     format=serialization.PrivateFormat.Raw,
    #     encryption_algorithm=serialization.NoEncryption()
    # ))


def generate_public_key(private_key: bytes):
    """Generates WireGuard public keys.

    Returns:
        A bytes object.

    Typical usage example::

        from pywireguard.base.util import generate_public_key
        ...
        peer = Peer(
            generate_public_key(private_key),
            preshared_key=preshared_key
        )
    """
    private_key = X25519PrivateKey.from_private_bytes(b64decode(private_key))
    return b64encode(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    )
