from ..interface import Interface
from ..peer import Peer


class LinuxPeer(Peer):
    def update(self, interface: Interface) -> None:
        pass

    def serialize(self):
        result = dict(
            public_key=self.public_key
        )
        if self.preshared_key is not None:
            result['preshared_key'] = self.preshared_key
        if self.endpoint is not None:
            result['endpoint'] = self.endpoint
        if self.allowed_ips is not None:
            result['allowed_ips'] = self.allowed_ips
        if self.persistent_keepalive_interval is not None:
            result['persistent_keepalive'] = self.persistent_keepalive_interval

        return result
