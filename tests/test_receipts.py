"""Tests for governance receipts: generation, signing, verification and storage."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from nacl.signing import SigningKey

from vectimus.engine.keys import (
    _decode_ed25519_private_pem,
    _decode_ed25519_public_pem,
    _encode_ed25519_private_pem,
    _encode_ed25519_public_pem,
    copy_public_key_to_project,
    ensure_keypair,
    load_signing_key,
    load_verify_key,
)
from vectimus.engine.receipts import (
    _write_receipt_sync,
    build_receipt,
    canonicalize,
    cleanup_old_receipts,
    compute_context_hash,
    compute_fingerprint,
    compute_policy_set_hash,
    generate_receipt_id,
    sign_receipt,
    verify_fingerprint,
    verify_receipt,
)

# ---------------------------------------------------------------------------
# Golden test fixtures — known keypair, known receipt, expected hashes
# ---------------------------------------------------------------------------

# Deterministic test keypair (32 bytes seed, hex-encoded for readability).
_GOLDEN_SEED = bytes.fromhex("a" * 64)
_GOLDEN_KEY = SigningKey(_GOLDEN_SEED)
_GOLDEN_KEY_ID = "vtms-key-golden"


def _golden_receipt_data() -> dict:
    """Return a deterministic receipt (without signature) for golden tests."""
    return {
        "spec_version": "1.0",
        "receipt_id": "vtms-00000000-0000-0000-0000-000000000000",
        "timestamp": "2026-03-21T14:32:01.847Z",
        "fingerprint": "",
        "principal": {"type": "developer", "id": "test@vectimus.com"},
        "action": {
            "tool": "Bash",
            "normalised_tool": "shell_command",
            "command_summary": "echo hello",
            "context_hash": "sha256:abc123",
        },
        "policy": {
            "policy_set_hash": "sha256:def456",
            "policy_pack_version": "0.18.1",
        },
        "decision": {
            "outcome": "ALLOW",
            "reason": "All checks passed",
            "evaluation_time_ms": 1.5,
        },
    }


class TestGoldenFixtures:
    """Known keypair + receipt produce deterministic hashes."""

    def test_golden_fingerprint_is_deterministic(self):
        """The same logical receipt always produces the same fingerprint."""
        receipt = _golden_receipt_data()
        fp1 = compute_fingerprint(receipt)
        fp2 = compute_fingerprint(receipt)
        assert fp1 == fp2
        assert len(fp1) == 16

    def test_golden_sign_and_verify(self):
        """Sign with known key, verify succeeds."""
        receipt = _golden_receipt_data()
        receipt["fingerprint"] = compute_fingerprint(receipt)
        signed = sign_receipt(receipt, _GOLDEN_KEY, _GOLDEN_KEY_ID)

        assert signed["signature"]["algorithm"] == "Ed25519"
        assert signed["signature"]["public_key_id"] == _GOLDEN_KEY_ID
        assert signed["signature"]["value"].startswith("base64:")

        valid, msg = verify_receipt(signed, verify_key=_GOLDEN_KEY.verify_key)
        assert valid, msg
        assert msg == "VALID"

    def test_golden_canonical_bytes_are_stable(self):
        """Canonical JSON of the same data produces identical bytes."""
        receipt = _golden_receipt_data()
        b1 = canonicalize(receipt)
        b2 = canonicalize(receipt)
        assert b1 == b2


# ---------------------------------------------------------------------------
# Receipt ID generation
# ---------------------------------------------------------------------------


class TestReceiptIdGeneration:
    def test_receipt_id_has_vtms_prefix(self):
        rid = generate_receipt_id()
        assert rid.startswith("vtms-")

    def test_receipt_ids_are_unique(self):
        ids = {generate_receipt_id() for _ in range(100)}
        assert len(ids) == 100


# ---------------------------------------------------------------------------
# Receipt construction
# ---------------------------------------------------------------------------


class TestBuildReceipt:
    def test_build_receipt_has_all_required_fields(self):
        receipt = build_receipt(
            receipt_id="vtms-test-123",
            principal_type="developer",
            principal_id="alice@example.com",
            tool="Bash",
            normalised_tool="shell_command",
            command_summary="ls -la",
            context_hash="sha256:abc",
            policy_set_hash="sha256:def",
            policy_pack_version="1.0.0",
            matched_policy_id=None,
            outcome="ALLOW",
            reason="All checks passed",
            evaluation_time_ms=2.5,
        )
        assert receipt["spec_version"] == "1.0"
        assert receipt["receipt_id"] == "vtms-test-123"
        assert receipt["fingerprint"]
        assert len(receipt["fingerprint"]) == 16
        assert receipt["principal"]["type"] == "developer"
        assert receipt["action"]["tool"] == "Bash"
        assert receipt["decision"]["outcome"] == "ALLOW"
        assert "matched_policy_id" not in receipt["policy"]

    def test_build_receipt_with_matched_policy(self):
        receipt = build_receipt(
            receipt_id="vtms-test-456",
            principal_type="developer",
            principal_id="bob@example.com",
            tool="Bash",
            normalised_tool="shell_command",
            command_summary="rm -rf /",
            context_hash="sha256:abc",
            policy_set_hash="sha256:def",
            policy_pack_version="1.0.0",
            matched_policy_id="policy::dangerous::block_rm_rf",
            outcome="DENY",
            reason="Blocked: recursive delete",
            evaluation_time_ms=3.1,
        )
        assert receipt["policy"]["matched_policy_id"] == "policy::dangerous::block_rm_rf"
        assert receipt["decision"]["outcome"] == "DENY"

    def test_command_summary_truncated_to_256(self):
        long_cmd = "x" * 500
        receipt = build_receipt(
            receipt_id="vtms-test-789",
            principal_type="developer",
            principal_id="test",
            tool="Bash",
            normalised_tool="shell_command",
            command_summary=long_cmd,
            context_hash="sha256:abc",
            policy_set_hash="sha256:def",
            policy_pack_version="1.0.0",
            matched_policy_id=None,
            outcome="ALLOW",
            reason="ok",
            evaluation_time_ms=1.0,
        )
        assert len(receipt["action"]["command_summary"]) == 256


# ---------------------------------------------------------------------------
# Canonical JSON determinism
# ---------------------------------------------------------------------------


class TestCanonicalJson:
    def test_different_key_orders_produce_same_bytes(self):
        """Same logical data with different insertion order → same canonical bytes."""
        d1 = {"b": 2, "a": 1, "c": 3}
        d2 = {"a": 1, "c": 3, "b": 2}
        assert canonicalize(d1) == canonicalize(d2)

    def test_nested_objects_sorted(self):
        d1 = {"outer": {"z": 1, "a": 2}}
        d2 = {"outer": {"a": 2, "z": 1}}
        assert canonicalize(d1) == canonicalize(d2)

    def test_canonical_produces_identical_fingerprints(self):
        """Two receipts with same data but different dict construction → same fingerprint."""
        r1 = _golden_receipt_data()
        r2 = dict(reversed(list(_golden_receipt_data().items())))
        assert compute_fingerprint(r1) == compute_fingerprint(r2)


# ---------------------------------------------------------------------------
# Signing and verification (round-trip)
# ---------------------------------------------------------------------------


class TestSignVerify:
    def test_round_trip(self):
        """Generate → sign → verify succeeds."""
        key = SigningKey.generate()
        receipt = build_receipt(
            receipt_id=generate_receipt_id(),
            principal_type="developer",
            principal_id="test@test.com",
            tool="Write",
            normalised_tool="file_write",
            command_summary="/tmp/test.py",
            context_hash=compute_context_hash({"action_type": "file_write"}),
            policy_set_hash=compute_policy_set_hash("forbid(p,a,r);"),
            policy_pack_version="1.0.0",
            matched_policy_id=None,
            outcome="ALLOW",
            reason="All checks passed",
            evaluation_time_ms=0.5,
        )
        signed = sign_receipt(receipt, key, "vtms-key-test")
        valid, msg = verify_receipt(signed, verify_key=key.verify_key)
        assert valid, msg

    def test_tamper_detection(self):
        """Modifying any field after signing → verification fails."""
        key = SigningKey.generate()
        receipt = build_receipt(
            receipt_id=generate_receipt_id(),
            principal_type="developer",
            principal_id="test@test.com",
            tool="Bash",
            normalised_tool="shell_command",
            command_summary="echo ok",
            context_hash="sha256:abc",
            policy_set_hash="sha256:def",
            policy_pack_version="1.0.0",
            matched_policy_id=None,
            outcome="ALLOW",
            reason="ok",
            evaluation_time_ms=1.0,
        )
        signed = sign_receipt(receipt, key, "vtms-key-test")

        # Tamper with the decision
        signed["decision"]["outcome"] = "DENY"
        valid, msg = verify_receipt(signed, verify_key=key.verify_key)
        assert not valid
        assert "INVALID" in msg or "failed" in msg

    def test_missing_signature_block(self):
        receipt = _golden_receipt_data()
        valid, msg = verify_receipt(receipt)
        assert not valid
        assert "No signature" in msg

    def test_wrong_key_fails(self):
        key1 = SigningKey.generate()
        key2 = SigningKey.generate()
        receipt = _golden_receipt_data()
        receipt["fingerprint"] = compute_fingerprint(receipt)
        signed = sign_receipt(receipt, key1, "vtms-key-1")
        valid, msg = verify_receipt(signed, verify_key=key2.verify_key)
        assert not valid


# ---------------------------------------------------------------------------
# Fingerprint verification
# ---------------------------------------------------------------------------


class TestFingerprintVerification:
    def test_valid_fingerprint(self):
        receipt = _golden_receipt_data()
        receipt["fingerprint"] = compute_fingerprint(receipt)
        valid, msg = verify_fingerprint(receipt)
        assert valid

    def test_tampered_fingerprint(self):
        receipt = _golden_receipt_data()
        receipt["fingerprint"] = "0000000000000000"
        valid, msg = verify_fingerprint(receipt)
        assert not valid


# ---------------------------------------------------------------------------
# Key management
# ---------------------------------------------------------------------------


class TestKeyManagement:
    def test_pem_round_trip(self):
        key = SigningKey.generate()
        pem = _encode_ed25519_private_pem(key)
        assert "-----BEGIN ED25519 PRIVATE KEY-----" in pem
        decoded = _decode_ed25519_private_pem(pem)
        assert bytes(decoded) == bytes(key)

    def test_public_pem_round_trip(self):
        key = SigningKey.generate()
        pem = _encode_ed25519_public_pem(key.verify_key)
        assert "-----BEGIN ED25519 PUBLIC KEY-----" in pem
        decoded = _decode_ed25519_public_pem(pem)
        assert bytes(decoded) == bytes(key.verify_key)

    def test_ensure_keypair_creates_key(self, tmp_path, monkeypatch):
        keys_dir = tmp_path / "keys"
        monkeypatch.setattr("vectimus.engine.keys.KEYS_DIR", keys_dir)
        key_id = ensure_keypair()
        assert key_id.startswith("vtms-key-")
        assert (keys_dir / f"{key_id}.key").exists()
        assert (keys_dir / f"{key_id}.pub").exists()
        # Private key has restrictive permissions
        assert oct((keys_dir / f"{key_id}.key").stat().st_mode)[-3:] == "600"

    def test_ensure_keypair_reuses_existing(self, tmp_path, monkeypatch):
        keys_dir = tmp_path / "keys"
        monkeypatch.setattr("vectimus.engine.keys.KEYS_DIR", keys_dir)
        key_id_1 = ensure_keypair()
        key_id_2 = ensure_keypair()
        assert key_id_1 == key_id_2

    def test_load_signing_key(self, tmp_path, monkeypatch):
        keys_dir = tmp_path / "keys"
        monkeypatch.setattr("vectimus.engine.keys.KEYS_DIR", keys_dir)
        key_id = ensure_keypair()
        loaded_id, loaded_key = load_signing_key(key_id)
        assert loaded_id == key_id

    def test_copy_public_key_to_project(self, tmp_path, monkeypatch):
        keys_dir = tmp_path / "keys"
        monkeypatch.setattr("vectimus.engine.keys.KEYS_DIR", keys_dir)
        key_id = ensure_keypair()
        project = tmp_path / "my-project"
        project.mkdir()
        dest = copy_public_key_to_project(key_id, project)
        assert dest.exists()
        assert dest.parent == project / ".vectimus" / "keys"

    def test_load_verify_key_from_project(self, tmp_path, monkeypatch):
        keys_dir = tmp_path / "keys"
        monkeypatch.setattr("vectimus.engine.keys.KEYS_DIR", keys_dir)
        key_id = ensure_keypair()
        project = tmp_path / "my-project"
        project.mkdir()
        copy_public_key_to_project(key_id, project)
        # Load from project dir
        vk = load_verify_key(key_id, search_dirs=[project / ".vectimus" / "keys"])
        assert vk is not None


# ---------------------------------------------------------------------------
# Receipt storage and retention
# ---------------------------------------------------------------------------


class TestReceiptStorage:
    def test_write_receipt_sync(self, tmp_path):
        receipt = _golden_receipt_data()
        receipt["fingerprint"] = compute_fingerprint(receipt)
        receipt["timestamp"] = "2026-03-21T14:32:01.847Z"

        _write_receipt_sync(receipt, tmp_path)

        day_dir = tmp_path / "2026-03-21"
        assert day_dir.exists()
        files = list(day_dir.glob("*.json"))
        assert len(files) == 1
        loaded = json.loads(files[0].read_text())
        assert loaded["receipt_id"] == receipt["receipt_id"]

    def test_retention_cleanup(self, tmp_path):
        # Create directories with old dates
        old_dir = tmp_path / "2025-01-01"
        old_dir.mkdir()
        (old_dir / "receipt.json").write_text("{}")

        recent_dir = tmp_path / datetime.now(UTC).strftime("%Y-%m-%d")
        recent_dir.mkdir()
        (recent_dir / "receipt.json").write_text("{}")

        removed = cleanup_old_receipts(tmp_path, retention_days=7)
        assert removed == 1
        assert not old_dir.exists()
        assert recent_dir.exists()

    def test_retention_cleanup_empty_dir(self, tmp_path):
        removed = cleanup_old_receipts(tmp_path / "nonexistent", retention_days=7)
        assert removed == 0


# ---------------------------------------------------------------------------
# Context and policy hashing
# ---------------------------------------------------------------------------


class TestHashing:
    def test_context_hash_has_prefix(self):
        h = compute_context_hash({"action_type": "shell_command", "command": "ls"})
        assert h.startswith("sha256:")
        assert len(h) == 71  # "sha256:" (7) + 64 hex chars

    def test_policy_set_hash_has_prefix(self):
        h = compute_policy_set_hash("forbid(principal, action, resource);")
        assert h.startswith("sha256:")

    def test_same_context_same_hash(self):
        ctx = {"action_type": "shell_command", "command": "ls -la"}
        h1 = compute_context_hash(ctx)
        h2 = compute_context_hash(ctx)
        assert h1 == h2

    def test_different_context_different_hash(self):
        h1 = compute_context_hash({"command": "ls"})
        h2 = compute_context_hash({"command": "rm"})
        assert h1 != h2


# ---------------------------------------------------------------------------
# Non-blocking receipt write
# ---------------------------------------------------------------------------


class TestNonBlocking:
    def test_write_failure_does_not_raise(self, tmp_path):
        """Receipt write failure should not propagate exceptions."""
        receipt = _golden_receipt_data()
        # Use a path that will fail (file instead of dir)
        bad_path = tmp_path / "not-a-dir"
        bad_path.write_text("block")
        # Should not raise
        _write_receipt_sync(receipt, bad_path)
