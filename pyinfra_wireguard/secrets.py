import subprocess


def get_pass(filename: str) -> str:
    """Get the data from the password manager."""
    try:
        r = subprocess.run(["pass", "show", filename], capture_output=True)
    except FileNotFoundError:
        print(f"Please install pass and pull the latest version of our pass secrets")
        exit()
    return r.stdout.decode('utf-8')


def generate_private_wg_key_locally() -> (str, str):
    """Generate a wireguard keypair locally

    :return The private key and the public key as a tuple
    """
    try:
        privkey = subprocess.run(["wg", "genkey"], capture_output=True).stdout.decode('utf-8').strip()
        pubkey = subprocess.run(["wg", "pubkey", privkey], capture_output=True).stdout.decode('utf-8').strip()
    except FileNotFoundError:
        print("Can't run `wg genkey`, have you installed wireguard-tools on your local machine?")
        exit(1)
    return privkey, pubkey


def store_public_key_in_pass(pubkey: str, pass_entry: str):
    """Store the PublicKey of a wireguard node in pass """
    status_quo = get_pass(pass_entry)
    if pubkey != status_quo:
        try:
            subprocess.run(["echo", pubkey, "|", "pass", "insert", "-e", pass_entry])
        except FileNotFoundError:
            print(f"Please install pass and pull the latest version of our pass secrets")
            exit()
        print(f"Added PublicKey to {pass_entry} - please re-deploy the mother to add the child as a peer.")
