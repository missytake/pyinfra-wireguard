from io import StringIO

from pyinfra import host
from pyinfra.api.deploy import deploy
from pyinfra.operations import apt, files, systemd
from pyinfra.facts.files import FindInFile

from .secrets import generate_private_wg_key_locally, store_public_key_in_pass


PEER_CONFIG = """
# %s
[Peer]
PublicKey = %s
AllowedIps = %s
Endpoint = %s
PersistentKeepalive = 25
"""


def peer_config(peer: str, pubkey: str, allowed_ips: str, endpoint: str) -> str:
    """Return config for a peer to add to the wg0.conf file of the wireguard node.

    :param peer: the hostname of the peer
    :param pubkey: the PublicKey
    :param allowed_ips: the wireguard-internal AllowedIps
    :param endpoint: the Endpoint of the peer, must be publically reachable without wireguard
    :return: the config snippet of this specific peer
    """
    return PEER_CONFIG % (peer, pubkey, allowed_ips, endpoint)


CHILD_CONFIG = """
[Interface]
PrivateKey = %s
Address = %s
"""


def full_config(privkey: str, address: str, peers: [tuple]) -> str:
    """Generate the config file for a wireguard node.

    :param privkey: the wireguard Private Key of the child
    :param address: the wireguard-internal IP address of the child
    :param peers: a list with a tuple for each peer, containing hostname, PublicKey, AllowedIps, and Endpoint
    :return: the config to be uploaded
    """
    config = CHILD_CONFIG % (privkey, address)
    for peer in peers:
        peer, pubkey, allowed_ips, endpoint = peer
        config += peer_config(peer, pubkey, allowed_ips, endpoint)
    return config


@deploy("Deploy WireGuard child")
def deploy_wg_child(address: str, mother: str, m_pubkey: str, m_allowed_ips: str, m_endpoint: str, pass_entry=""):
    """Deploy wireguard on a child node, configured to connect to a mother node.

    :param address: the wireguard-internal IP of the child
    :param mother: the hostname of the mother
    :param m_pubkey: the PublicKey of the mother
    :param m_allowed_ips: the AllowedIps of the mother
    :param m_endpoint: the Endpoint of the mother, must be publically reachable without wireguard
    :param pass_entry: (optional) the pass entry the child's public key should be saved to.
    """
    apt.packages(packages=["wireguard"])

    if not host.get_fact(FindInFile, "/etc/wireguard/wg0.conf", "PrivateKey = "):
        privkey, pubkey = generate_private_wg_key_locally()
        peers = [(mother, m_pubkey, m_allowed_ips, m_endpoint)]
        files.put(
            src=StringIO(full_config(privkey, address, peers)),
            dest="/etc/wireguard/wg0.conf",
            mode="600",
        )
        if pass_entry:
            store_public_key_in_pass(pubkey, pass_entry)

    systemd.service(
        name="Enable wireguard",
        service="wg-quick@wg0",
        enabled=True,
        running=True,
    )


@deploy("Deploy WireGuard mother")
def deploy_wg_mother(address: str, listen_port: str, peers: [tuple]):
    """

    :param address:
    :param listen_port:
    :param peers:
    :return:
    """