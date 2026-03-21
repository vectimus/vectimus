"""Ed25519 key management for governance receipts.

Keys live in ``~/.vectimus/keys/``.  One keypair per developer, shared
across all projects on the machine.  Project public keys are copied into
``.vectimus/keys/`` for verification by teammates.
"""

from __future__ import annotations

import base64
import os
import secrets
from pathlib import Path

import structlog
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey, VerifyKey

logger = structlog.get_logger(__name__)

KEYS_DIR = Path.home() / ".vectimus" / "keys"
KEY_PREFIX = "vtms-key-"


def _generate_key_id() -> str:
    """Return a new key ID: ``vtms-key-`` plus 6 random hex chars."""
    return KEY_PREFIX + secrets.token_hex(3)


def ensure_keypair() -> str:
    """Ensure an Ed25519 keypair exists in ``~/.vectimus/keys/``.

    If a ``.key`` file already exists, returns its key ID.  Otherwise
    generates a new keypair and writes it to disk with restrictive
    permissions on the private key.

    Returns the key ID (e.g. ``vtms-key-a1b2c3``).
    """
    KEYS_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

    # Check for existing key
    for entry in KEYS_DIR.iterdir():
        if entry.suffix == ".key" and entry.stem.startswith(KEY_PREFIX):
            key_id = entry.stem
            logger.info("using_existing_key", key_id=key_id)
            return key_id

    # Generate new keypair
    key_id = _generate_key_id()
    signing_key = SigningKey.generate()

    private_path = KEYS_DIR / f"{key_id}.key"
    public_path = KEYS_DIR / f"{key_id}.pub"

    # Write private key (PEM-like format)
    private_pem = _encode_ed25519_private_pem(signing_key)
    _write_restricted(private_path, private_pem)

    # Write public key
    public_pem = _encode_ed25519_public_pem(signing_key.verify_key)
    public_path.write_text(public_pem)

    logger.info("generated_new_keypair", key_id=key_id)
    return key_id


def load_signing_key(key_id: str | None = None) -> tuple[str, SigningKey]:
    """Load the Ed25519 signing key from ``~/.vectimus/keys/``.

    If *key_id* is None, discovers the first available key.
    Returns ``(key_id, SigningKey)``.
    """
    if key_id is None:
        key_id = _discover_key_id()
        if key_id is None:
            raise FileNotFoundError("No signing key found in ~/.vectimus/keys/")

    private_path = KEYS_DIR / f"{key_id}.key"
    if not private_path.exists():
        raise FileNotFoundError(f"Private key not found: {private_path}")

    pem_text = private_path.read_text()
    signing_key = _decode_ed25519_private_pem(pem_text)
    return key_id, signing_key


def load_verify_key(key_id: str, search_dirs: list[Path] | None = None) -> VerifyKey:
    """Load an Ed25519 public key for verification.

    Searches in *search_dirs* (project ``.vectimus/keys/``) and then
    the global ``~/.vectimus/keys/``.
    """
    search = list(search_dirs or []) + [KEYS_DIR]
    for d in search:
        pub_path = d / f"{key_id}.pub"
        if pub_path.exists():
            pem_text = pub_path.read_text()
            return _decode_ed25519_public_pem(pem_text)

    raise FileNotFoundError(
        f"Public key '{key_id}' not found in {[str(d) for d in search]}"
    )


def copy_public_key_to_project(key_id: str, project_root: Path) -> Path:
    """Copy the public key into the project's ``.vectimus/keys/`` directory.

    Returns the destination path.
    """
    src = KEYS_DIR / f"{key_id}.pub"
    if not src.exists():
        raise FileNotFoundError(f"Public key not found: {src}")

    dest_dir = project_root / ".vectimus" / "keys"
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{key_id}.pub"
    dest.write_text(src.read_text())
    return dest


def _discover_key_id() -> str | None:
    """Find the first key ID in ``~/.vectimus/keys/``."""
    if not KEYS_DIR.exists():
        return None
    for entry in KEYS_DIR.iterdir():
        if entry.suffix == ".key" and entry.stem.startswith(KEY_PREFIX):
            return entry.stem
    return None


# -- PEM encoding/decoding -------------------------------------------------


def _encode_ed25519_private_pem(key: SigningKey) -> str:
    """Encode an Ed25519 private key as PEM."""
    raw = bytes(key)
    b64 = base64.b64encode(raw).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return f"-----BEGIN ED25519 PRIVATE KEY-----\n{body}\n-----END ED25519 PRIVATE KEY-----\n"


def _decode_ed25519_private_pem(pem: str) -> SigningKey:
    """Decode a PEM-encoded Ed25519 private key."""
    lines = pem.strip().splitlines()
    b64 = "".join(line for line in lines if not line.startswith("-----"))
    raw = base64.b64decode(b64)
    return SigningKey(raw, encoder=RawEncoder)


def _encode_ed25519_public_pem(key: VerifyKey) -> str:
    """Encode an Ed25519 public key as PEM."""
    raw = bytes(key)
    b64 = base64.b64encode(raw).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    body = "\n".join(lines)
    return f"-----BEGIN ED25519 PUBLIC KEY-----\n{body}\n-----END ED25519 PUBLIC KEY-----\n"


def _decode_ed25519_public_pem(pem: str) -> VerifyKey:
    """Decode a PEM-encoded Ed25519 public key."""
    lines = pem.strip().splitlines()
    b64 = "".join(line for line in lines if not line.startswith("-----"))
    raw = base64.b64decode(b64)
    return VerifyKey(raw, encoder=RawEncoder)


def _write_restricted(path: Path, content: str) -> None:
    """Write content to a file with 0600 permissions."""
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        f = os.fdopen(fd, "w")
    except BaseException:
        os.close(fd)
        raise
    with f:
        f.write(content)
