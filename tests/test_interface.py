from src.pywireguard.base.exceptions import BadInterfaceName
from src.pywireguard.base.utils import generate_private_key, generate_public_key, generate_preshared_key
from src.pywireguard.factory import Interface, Peer


def test_interface():
    wgtest0 = Interface('wgtest0')
    private_key = generate_private_key()
    wgtest0.private_key = private_key
    assert wgtest0.private_key == private_key
    wgtest0.fwmark = 100
    assert wgtest0.fwmark == 100
    wgtest0.listen_port = 54230
    assert wgtest0.listen_port == 54230
    assert wgtest0.public_key == generate_public_key(private_key)


def test_bad_interface_name():
    try:
        Interface('wgtest1000')
        assert False
    except BadInterfaceName:
        assert True


def test_peer():
    wgtest0 = Interface('wgtest0')
    private_key = generate_private_key()
    public_key = generate_public_key(private_key)
    allowed_ips = ['192.168.0.0/24', '172.16.128.0/24']
    peer = Peer(
        public_key,
        preshared_key=generate_preshared_key(),
        allowed_ips=allowed_ips,
        endpoint='178.20.1.4:34567'
    )
    wgtest0.upsert_peer(peer)
    assert peer in wgtest0.peers
    peers = wgtest0.peers
    idx = peers.index(peer)
    peer = peers[idx]
    # Read all attributes
    _ = peer.rx_bytes
    _ = peer.tx_bytes
    _ = peer.last_handshake_time_sec
    _ = peer.last_handshake_time_nsec
    assert peer.public_key == public_key
    assert peer.allowed_ips == allowed_ips
    new_allowed_ips = ['192.168.0.0/24']
    peer.allowed_ips = new_allowed_ips
    peer.persistent_keepalive_interval = 10
    wgtest0.upsert_peer(peer)
    peers = wgtest0.peers
    idx = peers.index(peer)
    peer = peers[idx]
    assert peer.allowed_ips == new_allowed_ips
    assert peer.persistent_keepalive_interval == 10
    wgtest0.remove_peer(peer)
    assert peer not in wgtest0.peers
