from pywireguard.base.utils import generate_private_key, generate_public_key, generate_preshared_key
from pywireguard.factory import Interface, Peer


def test_interface():
    wgtest0 = Interface('wgtest0')
    private_key = generate_private_key()
    wgtest0.private_key = private_key
    assert wgtest0.private_key == private_key
    wgtest0.fwmark = 100
    assert wgtest0.fwmark == 100
    assert wgtest0.public_key == generate_public_key(private_key)


def test_peer():
    wgtest0 = Interface('wgtest0')
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    peer = Peer(
        public_key,
        preshared_key=generate_preshared_key()
    )
    wgtest0.upsert_peer(peer)
    assert peer in wgtest0.peers
    idx = wgtest0.peers.index(peer)
    peer = wgtest0.peers[idx]
    # Read all attributes
    _ = peer.rx_bytes
    _ = peer.tx_bytes
    _ = peer.last_handshake_time_sec
    _ = peer.last_handshake_time_nsec
    assert peer.public_key == public_key
