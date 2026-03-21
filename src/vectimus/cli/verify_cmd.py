"""``vectimus verify`` -- verify a governance receipt's signature."""

from __future__ import annotations

import json
from pathlib import Path

import click


@click.command("verify")
@click.argument("receipt_file", type=click.Path(exists=True, path_type=Path))
@click.option(
    "--public-key",
    type=click.Path(exists=True, path_type=Path),
    default=None,
    help="Path to the Ed25519 public key file.  Auto-discovered if omitted.",
)
def verify_cmd(receipt_file: Path, public_key: Path | None) -> None:
    """Verify a governance receipt's cryptographic signature.

    Works offline with no running Vectimus service or Cedar engine.

    \b
      vectimus verify .vectimus/receipts/2026-03-21/vtms-abc123.json
      vectimus verify receipt.json --public-key alice.pub
    """
    try:
        receipt = json.loads(receipt_file.read_text())
    except (json.JSONDecodeError, OSError) as exc:
        click.echo(f"Error reading receipt: {exc}", err=True)
        raise SystemExit(1)

    from vectimus.engine.receipts import verify_fingerprint, verify_receipt

    # Verify fingerprint first
    fp_valid, fp_msg = verify_fingerprint(receipt)
    if not fp_valid:
        click.echo(f"INVALID: {fp_msg}")
        raise SystemExit(1)

    # Prepare verify key
    verify_key = None
    search_dirs: list[Path] = []

    if public_key:
        from vectimus.engine.keys import _decode_ed25519_public_pem

        pem = public_key.read_text()
        verify_key = _decode_ed25519_public_pem(pem)
    else:
        # Search project .vectimus/keys/ directory
        project_keys = Path.cwd() / ".vectimus" / "keys"
        if project_keys.exists():
            search_dirs.append(project_keys)

    is_valid, message = verify_receipt(receipt, verify_key=verify_key, search_dirs=search_dirs)

    receipt_id = receipt.get("receipt_id", "unknown")
    fingerprint = receipt.get("fingerprint", "")

    if is_valid:
        click.echo("VALID")
        click.echo(f"  Receipt:     {receipt_id}")
        click.echo(f"  Fingerprint: {fingerprint}")
        click.echo(f"  Decision:    {receipt.get('decision', {}).get('outcome', '?')}")
        click.echo(f"  Signed by:   {receipt.get('signature', {}).get('public_key_id', '?')}")
    else:
        click.echo(f"INVALID: {message}")
        click.echo(f"  Receipt: {receipt_id}")
        raise SystemExit(1)
