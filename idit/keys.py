"""
Personal Idit — Key Management
Ed25519 keypair generation and loading for chain signers.
"""
import os
from pathlib import Path

from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import HexEncoder

DEFAULT_DATA_DIR = Path.home() / ".idit"


def keys_dir(data_dir: Path | None = None) -> Path:
    d = (data_dir or DEFAULT_DATA_DIR) / "keys"
    d.mkdir(parents=True, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def generate_keypair(name: str, data_dir: Path | None = None) -> dict:
    """Generate or load an Ed25519 keypair for a signer. Returns public key hex."""
    kdir = keys_dir(data_dir)
    key_path = kdir / f"{name}.key"
    pub_path = kdir / f"{name}.pub"

    if key_path.exists():
        with open(key_path, "r") as f:
            sk_hex = f.read().strip()
        sk = SigningKey(sk_hex, encoder=HexEncoder)
        pub_hex = sk.verify_key.encode(encoder=HexEncoder).decode()
        return {"name": name, "public_key": pub_hex, "status": "existing"}

    sk = SigningKey.generate()
    sk_hex = sk.encode(encoder=HexEncoder).decode()
    pub_hex = sk.verify_key.encode(encoder=HexEncoder).decode()

    with open(key_path, "w") as f:
        f.write(sk_hex)
    os.chmod(key_path, 0o600)

    with open(pub_path, "w") as f:
        f.write(pub_hex)

    return {"name": name, "public_key": pub_hex, "status": "generated"}


def load_signing_key(name: str, data_dir: Path | None = None) -> SigningKey:
    """Load a signer's private key."""
    key_path = keys_dir(data_dir) / f"{name}.key"
    if not key_path.exists():
        raise FileNotFoundError(f"No key for signer '{name}' at {key_path}")
    with open(key_path, "r") as f:
        return SigningKey(f.read().strip(), encoder=HexEncoder)


def load_verify_key(name: str, data_dir: Path | None = None) -> VerifyKey:
    """Load a signer's public key for verification."""
    pub_path = keys_dir(data_dir) / f"{name}.pub"
    if not pub_path.exists():
        raise FileNotFoundError(f"No public key for signer '{name}' at {pub_path}")
    with open(pub_path, "r") as f:
        return VerifyKey(f.read().strip(), encoder=HexEncoder)


def list_signers(data_dir: Path | None = None) -> list[dict]:
    """List all signers with public keys."""
    kdir = keys_dir(data_dir)
    signers = []
    for pub_file in sorted(kdir.glob("*.pub")):
        with open(pub_file, "r") as f:
            pub_hex = f.read().strip()
        signers.append({"name": pub_file.stem, "public_key": pub_hex})
    return signers
