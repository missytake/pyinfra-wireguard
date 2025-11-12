from io import StringIO

from pyinfra import host
from pyinfra.api.deploy import deploy
from pyinfra.operations import apt, files, systemd
from pyinfra.facts.files import FindInFile

from .secrets import generate_private_wg_key_locally, store_public_key_in_pass


CONFIG_PATH = "/etc/wireguard/wg0.conf"

PEER_CONFIG = """
# %s
[Peer]
PublicKey = %s
AllowedIps = %s
"""


def peer_config(peer: str, pubkey: str, allowed_ips: str, endpoint="") -> str:
    """Return config for a peer to add to the wg0.conf file of the wireguard node.

    :param peer: the hostname of the peer
    :param pubkey: the PublicKey
    :param allowed_ips: the wireguard-internal AllowedIps
    :param endpoint: (optional) the Endpoint of the peer, must be publically reachable without wireguard
    :return: the config snippet of this specific peer
    """
    peer_config = PEER_CONFIG % (peer, pubkey, allowed_ips)
    if endpoint:
        peer_config += f"Endpoint = {endpoint}\nPersistentKeepalive = 25\n"
    return peer_config


INTERFACE = """[Interface]
PrivateKey = %s
Address = %s
"""


def full_config(privkey: str, address: str, peers: [tuple], listen_port="") -> str:
    """Generate the config file for a wireguard node.

    :param privkey: the wireguard Private Key of the child
    :param address: the wireguard-internal IP address of the child
    :param peers: a list with a tuple for each peer, containing hostname, PublicKey, AllowedIps, and Endpoint
    :param listen_port: (optional) the port on which the node listens for peers who want to connect
    :return: the config to be uploaded
    """
    config = INTERFACE % (privkey, address)
    if listen_port:
        config += f"ListenPort = {listen_port}\n"
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

    if not host.get_fact(FindInFile, CONFIG_PATH, "PrivateKey = "):
        privkey, pubkey = generate_private_wg_key_locally()
        peers = [(mother, m_pubkey, m_allowed_ips, m_endpoint)]
        files.put(
            src=StringIO(full_config(privkey, address, peers)),
            dest=CONFIG_PATH,
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
def deploy_wg_mother(address: str, listen_port: str, peers: [tuple], pass_entry=""):
    """Deploy a wireguard mother node

    :param address: the wireguard-internal IP of the mother
    :param listen_port: the port on which it listens to children
    :param peers: a list of tuples for each child, with its hostname, PublicKey, and AllowedIps
    :param pass_entry: (optional) the pass entry the mother's public key should be saved to.
    """
    apt.packages(packages=["wireguard"])

    reload_config = False
    if not host.get_fact(FindInFile, CONFIG_PATH, "PrivateKey = "):
        privkey, pubkey = generate_private_wg_key_locally()
        interface = files.put(
            src=StringIO(full_config(privkey, address, [], listen_port=listen_port)),
            dest=CONFIG_PATH,
            mode="600",
        )
        reload_config |= interface.changed
        if pass_entry:
            store_public_key_in_pass(pubkey, pass_entry)

    for child in peers:
        hostname, pubkey, allowed_ips = child
        child_config = peer_config(hostname, pubkey, allowed_ips)
        peer_added = files.block(
            path=CONFIG_PATH,
            content=child_config,
            backup=True,
        )
        reload_config |= peer_added.changed

    systemd.service(
        name="Enable wireguard",
        service="wg-quick@wg0",
        enabled=True,
        running=True,
        restarted=reload_config,
    )
