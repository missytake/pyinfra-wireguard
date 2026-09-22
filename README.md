# pyinfra-wireguard

This is a pyinfra module to deploy a wireguard network.

It assumes a mother-child layout:

```
       mother
     /   |   \
child  child  child
```

This way, you can deploy monitoring or backup services on a mother node,
and all child nodes can send their traffic there.

## Usage

### 1. deploy mother node

To deploy a mother node, you can use this method in your deploy.py file:

```
from pyinfra-wireguard import deploy_wireguard_mother

deploy_wireguard_mother(
    address="192.168.10.1/24",      # Interface.Address parameter
    listen_port="51902",            # Interface.ListenPort parameter
    peers=[],                       # empty in the beginning
    pass_entry="wg/mother/pubkey",  # optional: store public key in pass
    _sudo=True,                     # if you don't deploy with root anyway
)
```

You can deploy this with an empty peers list in the beginning;
this will generate a private/public keypair,
store the private key in `/etc/wireguard/wg0.conf` on the server,
and save the public key in [pass](https://www.passwordstore.org/).
If you omit `pass_entry`, the public key will be printed;
you will need it later for configuring the children.

### 2. deploy child node

One of those children can then be deployed like this:

```
from pyinfra-wireguard import deploy_wireguard_child

deploy_wireguard_child(
    address="192.168.10.2",             # Interface.Address parameter
    mother="mother",                    # human-readable name of the mother
    m_pubkey="aod...AiU=",              # The mother's public key from the previous step
    m_allowed_ips="192.168.10.1/32",    # Peers.Mother.AllowedIps parameter
    m_endpoint="sarai.test.org:51902",  # Peers.Mother.Endpoint parameter
    pass_entry="wg/isaac/pubkey",       # optional: store public key in pass
    _sudo=True,                         # if you don't deploy with root anyway
)
```

Again, if you don't have pass set up,
the public key will be printed,
as we also need to add it to the mother's config.

### 3. re-deploy mother to add child

Now we can amend the mother's deploy.py file
to include the child's public key and address:

```
from pyinfra-wireguard import deploy_wireguard_mother

children = [
    (
        "isaac",                # human-readable name
        "mjs...J2Hg=",          # wireguard public key
        "192.168.10.2/32",      # wireguard-internal address of
        "isaac.test.org:51902"  # optional: publically reachable end-point
    ),
]

deploy_wireguard_mother(
    address="192.168.10.1/24",      # Interface.Address parameter
    listen_port="51902",            # Interface.ListenPort parameter
    peers=children,                 # empty in the beginning
    pass_entry="wg/mother/pubkey",  # optional: store public key in pass
    _sudo=True,                     # if you don't deploy with root anyway
)
```

If your child node does not have a publically reachable endpoint,
you can also leave the last string empty.
It is only useful so both sides can initiate a connection,
which improves connectivity in some cases.
