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

INTERFACE = "[Interface]\nPrivateKey = "


def generate_peer_config(peer: str, pubkey: str, allowed_ips: str, endpoint="") -> str:
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


@deploy("Deploy WireGuard child")
def deploy_wireguard_child(address: str, mother: str, m_pubkey: str, m_allowed_ips: str, m_endpoint: str, listen_port="", pass_entry="", **pyinfra_args):
    """Deploy wireguard on a child node, configured to connect to a mother node.

    :param address: the wireguard-internal IP of the child
    :param mother: the hostname of the mother
    :param m_pubkey: the PublicKey of the mother
    :param m_allowed_ips: the AllowedIps of the mother
    :param m_endpoint: the Endpoint of the mother, must be publically reachable without wireguard
    :param listen_port: the port to listen on, so others can reach the node's endpoint
    :param pass_entry: (optional) the pass entry the child's public key should be saved to.
    :param pyinfra_args: pyinfra arguments like _sudo=True
    """
    mother_as_peer = [(mother, m_pubkey, m_allowed_ips, m_endpoint)]
    update_config(address, mother_as_peer, listen_port=listen_port, pass_entry=pass_entry, **pyinfra_args)


@deploy("Deploy WireGuard mother")
def deploy_wireguard_mother(address: str, peers: [tuple], listen_port: str = "51902", pass_entry="", **pyinfra_args):
    """Deploy a wireguard mother node

    :param address: the wireguard-internal IP of the mother
    :param peers: a list of tuples for each child, with its hostname, PublicKey, AllowedIps, and Endpoint
    :param listen_port: the port on which it listens to children
    :param pass_entry: (optional) the pass entry the mother's public key should be saved to.
    :param pyinfra_args: pyinfra arguments like _sudo=True
    """
    update_config(address, peers, listen_port=listen_port, pass_entry=pass_entry, **pyinfra_args)


def update_config(address: str, peers: [tuple], listen_port: str = "", pass_entry="", **pyinfra_args):
    """Generate and upload config for a wireguard node

    :param address: the wireguard-internal IP of the mother
    :param peers: a list of tuples for each child, with its hostname, PublicKey, AllowedIps, and Endpoint
    :param listen_port: the port on which it listens to children
    :param pass_entry: (optional) the pass entry the mother's public key should be saved to.
    :param pyinfra_args: pyinfra arguments like _sudo=True
    """
    apt.packages(packages=["wireguard"], **pyinfra_args)

    reload_config = False
    if not host.get_fact(FindInFile, CONFIG_PATH, "PrivateKey = "):
        privkey, pubkey = generate_private_wg_key_locally()
        interface_op = files.put(
            name="Deploy initial config with generated private key",
            src=StringIO(INTERFACE + privkey),
            dest=CONFIG_PATH,
            mode="600",
            **pyinfra_args,
        )
        reload_config |= interface_op.changed
        if pass_entry:
            store_public_key_in_pass(pubkey, pass_entry)
        else:
            print("Generated wireguard public key: " + pubkey)

    address_op = files.line(
        name="Set wireguard Address",
        path=CONFIG_PATH,
        line="^(#|)Address = (.*)",
        replace=f"Address = {address}",
        extended_regex=True,
    )
    listen_port_op = files.line(
        name="Set wireguard ListenPort",
        path=CONFIG_PATH,
        line="^(#|)ListenPort = (.*)",
        replace=f"ListenPort = {listen_port}",
        present=bool(listen_port),
        extended_regex=True,
    )

    peers_config = ""
    for hostname, pubkey, allowed_ips, endpoint in peers:
        peers_config += generate_peer_config(hostname, pubkey, allowed_ips, endpoint=endpoint)
    peer_added = files.block(
        path=CONFIG_PATH,
        content=peers_config,
        **pyinfra_args,
    )

    reload_config |= address_op.changed or listen_port_op.changed or peer_added.changed
    systemd.service(
        name="Enable wireguard",
        service="wg-quick@wg0",
        enabled=True,
        running=True,
        restarted=reload_config,
        **pyinfra_args,
    )
