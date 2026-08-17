"""Manifest signing with Post-Quantum Cryptography (ML-DSA-65)."""

from __future__ import annotations

import argparse
from pathlib import Path

from bootsentry.crypto.keys import load_secret_key
from bootsentry.crypto.manifest import Manifest
from bootsentry.crypto.provider import get_provider


def sign_manifest(
    manifest: Manifest,
    secret_key_bytes: bytes,
    algorithm: str | None = None,
) -> Manifest:
    """Sign the canonical manifest representation with the specified secret key."""
    alg = algorithm or manifest.algorithm
    provider = get_provider(alg)
    canonical_bytes = manifest.canonical_bytes()

    sig_bytes = provider.sign(secret_key_bytes, canonical_bytes)
    manifest.algorithm = alg
    manifest.signature = sig_bytes.hex()
    return manifest


def sign_stage_manifest_file(
    manifest_path: Path | str,
    private_key_path: Path | str,
    out_path: Path | str | None = None,
) -> Manifest:
    """Load manifest and private key, compute PQC signature, and save signed manifest."""
    manifest = Manifest.load(manifest_path)
    _, _, sk_bytes = load_secret_key(private_key_path)

    signed_manifest = sign_manifest(manifest, sk_bytes)
    save_dest = out_path or manifest_path
    signed_manifest.save(save_dest)
    return signed_manifest


def main() -> None:
    parser = argparse.ArgumentParser(description="Sign BootSentry Stage Manifests with PQC")
    parser.add_argument("--keys-dir", type=str, default="config/keys", help="Keys directory")
    parser.add_argument(
        "--stages-dir", type=str, default="config/stages", help="Stage manifests directory"
    )
    args = parser.parse_args()

    stages_dir = Path(args.stages_dir)
    keys_dir = Path(args.keys_dir)

    for stage_id in ["s0", "s1", "s2", "s3"]:
        m_file = stages_dir / f"{stage_id}_manifest.json"
        k_file = keys_dir / f"{stage_id}_private.json"
        if m_file.exists() and k_file.exists():
            sign_stage_manifest_file(m_file, k_file)
            print(f"[OK] Signed {stage_id.upper()} manifest ({m_file})")
        else:
            print(f"[-] Skipping {stage_id.upper()} (missing manifest or key)")


if __name__ == "__main__":
    main()
