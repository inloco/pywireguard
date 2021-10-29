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
elif sys.platform == 'win32':
    from .base.windows.interface import WindowsInterface
    from .base.userspace.peer import UserspacePeer

    Interface = WindowsInterface
    Peer = UserspacePeer
else:
    raise UnsupportedPlatform()
