"""Governance receipt generation, signing and verification.

A receipt is a cryptographic proof that a Cedar policy evaluation occurred.
It is signed with Ed25519, uses RFC 8785 canonical JSON for deterministic
hashing, and is stored as a standalone JSON file in ``.vectimus/receipts/``.

Receipts are generated asynchronously after the evaluation decision is
returned so they never block the hook response.
"""

from __future__ import annotations

import hashlib
import json
import sys
import threading
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import canonicaljson
import structlog
from nacl.encoding import RawEncoder
from nacl.signing import SigningKey, VerifyKey

from vectimus.engine.keys import load_verify_key

logger = structlog.get_logger(__name__)

SPEC_VERSION = "1.0"
RECEIPT_ID_PREFIX = "vtms-"


def generate_receipt_id() -> str:
    """Generate a receipt ID synchronously.  Fast (UUID4 only)."""
    return RECEIPT_ID_PREFIX + str(uuid.uuid4())


def build_receipt(
    *,
    receipt_id: str,
    principal_type: str,
    principal_id: str,
    tool: str,
    normalised_tool: str,
    command_summary: str,
    context_hash: str,
    policy_set_hash: str,
    policy_pack_version: str,
    matched_policy_id: str | None,
    outcome: str,
    reason: str,
    evaluation_time_ms: float,
) -> dict[str, Any]:
    """Construct the receipt dict (without signature)."""
    # Truncate command_summary to 256 chars
    if len(command_summary) > 256:
        command_summary = command_summary[:256]

    receipt: dict[str, Any] = {
        "spec_version": SPEC_VERSION,
        "receipt_id": receipt_id,
        "timestamp": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "fingerprint": "",  # filled after canonicalization
        "principal": {
            "type": principal_type,
            "id": principal_id,
        },
        "action": {
            "tool": tool,
            "normalised_tool": normalised_tool,
            "command_summary": command_summary,
            "context_hash": context_hash,
        },
        "policy": {
            "policy_set_hash": policy_set_hash,
            "policy_pack_version": policy_pack_version,
        },
        "decision": {
            "outcome": outcome,
            "reason": reason,
            "evaluation_time_ms": round(evaluation_time_ms, 1),
        },
    }

    if matched_policy_id:
        receipt["policy"]["matched_policy_id"] = matched_policy_id

    # Compute fingerprint
    receipt["fingerprint"] = compute_fingerprint(receipt)

    return receipt


def compute_fingerprint(receipt_without_sig: dict[str, Any]) -> str:
    """Compute the 16-hex-char fingerprint of a receipt (sans signature).

    Uses RFC 8785 canonical JSON → SHA-256 → first 16 hex chars.
    """
    canonical = canonicalize(receipt_without_sig)
    return hashlib.sha256(canonical).hexdigest()[:16]


def canonicalize(data: dict[str, Any]) -> bytes:
    """RFC 8785 canonical JSON serialization."""
    return canonicaljson.encode_canonical_json(data)


def compute_context_hash(action_context: dict[str, Any]) -> str:
    """SHA-256 hash of the canonicalized action context, prefixed with ``sha256:``."""
    canonical = canonicalize(action_context)
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def compute_policy_set_hash(policies_text: str) -> str:
    """SHA-256 hash of the policy set text, prefixed with ``sha256:``."""
    return "sha256:" + hashlib.sha256(policies_text.encode("utf-8")).hexdigest()


def sign_receipt(receipt: dict[str, Any], signing_key: SigningKey, key_id: str) -> dict[str, Any]:
    """Sign a receipt and return the complete receipt with signature block.

    Signs the canonical JSON of all fields except the ``signature`` block.
    """
    # Remove any existing signature
    receipt_to_sign = {k: v for k, v in receipt.items() if k != "signature"}

    canonical = canonicalize(receipt_to_sign)
    digest = hashlib.sha256(canonical).digest()
    signed = signing_key.sign(digest, encoder=RawEncoder)
    signature_bytes = signed.signature

    import base64

    receipt_with_sig = dict(receipt_to_sign)
    receipt_with_sig["signature"] = {
        "algorithm": "Ed25519",
        "public_key_id": key_id,
        "value": "base64:" + base64.b64encode(signature_bytes).decode("ascii"),
    }

    return receipt_with_sig


def verify_receipt(
    receipt: dict[str, Any],
    verify_key: VerifyKey | None = None,
    search_dirs: list[Path] | None = None,
) -> tuple[bool, str]:
    """Verify a receipt's signature.

    Returns ``(is_valid, message)``.

    If *verify_key* is not provided, the key is loaded using the
    ``public_key_id`` from the receipt's signature block.
    """
    sig_block = receipt.get("signature")
    if not sig_block:
        return False, "No signature block in receipt"

    key_id = sig_block.get("public_key_id", "")
    sig_value = sig_block.get("value", "")
    algorithm = sig_block.get("algorithm", "")

    if algorithm != "Ed25519":
        return False, f"Unsupported algorithm: {algorithm}"

    if not sig_value.startswith("base64:"):
        return False, "Invalid signature format (expected base64: prefix)"

    import base64

    try:
        signature_bytes = base64.b64decode(sig_value[7:])
    except Exception:
        return False, "Invalid base64 in signature"

    # Load verify key if not provided
    if verify_key is None:
        try:
            verify_key = load_verify_key(key_id, search_dirs=search_dirs)
        except FileNotFoundError as e:
            return False, str(e)

    # Reconstruct canonical hash
    receipt_without_sig = {k: v for k, v in receipt.items() if k != "signature"}
    canonical = canonicalize(receipt_without_sig)
    digest = hashlib.sha256(canonical).digest()

    # Verify
    try:
        verify_key.verify(digest, signature_bytes)
        return True, "VALID"
    except Exception:
        return False, "INVALID: signature verification failed"


def verify_fingerprint(receipt: dict[str, Any]) -> tuple[bool, str]:
    """Verify that the fingerprint in the receipt matches the computed one."""
    receipt_without_sig = {k: v for k, v in receipt.items() if k != "signature"}
    # Temporarily set fingerprint to "" for recomputation from other fields
    saved_fp = receipt_without_sig.get("fingerprint", "")

    # Recompute: the fingerprint was computed with the fingerprint field set to ""
    # Actually, the fingerprint was computed with the fingerprint field as-is in the receipt.
    # Let me re-read the build_receipt flow: fingerprint is set to "" first,
    # then compute_fingerprint is called which canonicalizes the whole receipt
    # (including fingerprint=""), then fingerprint is set to the result.
    # So to verify, we need to set fingerprint="" and recompute.
    receipt_for_fp = dict(receipt_without_sig)
    receipt_for_fp["fingerprint"] = ""
    expected = compute_fingerprint(receipt_for_fp)

    if saved_fp == expected:
        return True, f"Fingerprint valid: {saved_fp}"
    return False, f"Fingerprint mismatch: expected {expected}, got {saved_fp}"


# -- Async receipt writing --------------------------------------------------


def write_receipt_async(
    receipt: dict[str, Any],
    receipts_dir: Path,
) -> None:
    """Write a signed receipt to disk in a background thread.

    Never blocks the caller.  Failures are logged to stderr.
    """
    thread = threading.Thread(
        target=_write_receipt_sync,
        args=(receipt, receipts_dir),
        daemon=True,
    )
    thread.start()


def _write_receipt_sync(receipt: dict[str, Any], receipts_dir: Path) -> None:
    """Write receipt JSON to ``receipts_dir/{date}/{receipt_id}.json``."""
    try:
        # Parse date from timestamp
        ts = receipt.get("timestamp", "")
        date_str = ts[:10] if len(ts) >= 10 else datetime.now(UTC).strftime("%Y-%m-%d")

        day_dir = receipts_dir / date_str
        day_dir.mkdir(parents=True, exist_ok=True)

        receipt_id = receipt.get("receipt_id", "unknown")
        path = day_dir / f"{receipt_id}.json"
        path.write_text(json.dumps(receipt, indent=2) + "\n")
    except Exception as exc:
        print(f"vectimus: receipt write failed: {exc}", file=sys.stderr)


# -- Retention cleanup ------------------------------------------------------


def cleanup_old_receipts(receipts_dir: Path, retention_days: int = 7) -> int:
    """Delete receipt date directories older than *retention_days*.

    Returns the number of directories removed.
    """
    if not receipts_dir.exists():
        return 0

    from datetime import timedelta

    cutoff = datetime.now(UTC).date() - timedelta(days=retention_days)
    removed = 0

    for entry in sorted(receipts_dir.iterdir()):
        if not entry.is_dir():
            continue
        try:
            dir_date = datetime.strptime(entry.name, "%Y-%m-%d").date()
        except ValueError:
            continue
        if dir_date < cutoff:
            import shutil

            shutil.rmtree(entry)
            removed += 1
            logger.info("receipt_retention_cleanup", removed_dir=entry.name)

    return removed
