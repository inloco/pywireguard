import sys

from .base.exceptions import UnsupportedPlatform

if sys.platform == 'linux':
    from .base.linux.peer import LinuxPeer
    from .base.linux.interface import LinuxInterface

    Interface = LinuxInterface
    Peer = LinuxPeer
elif sys.platform == 'darwin':
    from .base.darwin.interface import DarwinInterface
    from .base.userspace.peer import UserspacePeer

    Interface = DarwinInterface
    Peer = UserspacePeer
else:
    raise UnsupportedPlatform()
