import sys

from .base.exceptions import UnsupportedPlatform

if sys.platform == 'linux':
    from .base.linux.peer import LinuxPeer
    from .base.linux.interface import LinuxInterface

    Interface = LinuxInterface
    Peer = LinuxPeer
else:
    raise UnsupportedPlatform()
