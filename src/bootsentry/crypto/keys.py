"""Key management and serialization for BootSentry PQC keys."""

from __future__ import annotations

import argparse
import json
from dataclasses import asdict, dataclass
from pathlib import Path

from bootsentry.crypto.provider import CryptoError, MalformedKeyError, get_provider


@dataclass(frozen=True)
class PQCKeypair:
    stage_id: str
    algorithm: str
    public_key_hex: str
    secret_key_hex: str

    @property
    def public_key_bytes(self) -> bytes:
        return bytes.fromhex(self.public_key_hex)

    @property
    def secret_key_bytes(self) -> bytes:
        return bytes.fromhex(self.secret_key_hex)

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    def public_dict(self) -> dict[str, str]:
        return {
            "stage_id": self.stage_id,
            "algorithm": self.algorithm,
            "public_key_hex": self.public_key_hex,
        }


def generate_stage_keypair(stage_id: str, algorithm: str = "ML-DSA-65") -> PQCKeypair:
    """Generate a fresh PQC keypair for a specific boot stage."""
    provider = get_provider(algorithm)
    pk_bytes, sk_bytes = provider.keygen()
    return PQCKeypair(
        stage_id=stage_id,
        algorithm=algorithm,
        public_key_hex=pk_bytes.hex(),
        secret_key_hex=sk_bytes.hex(),
    )


def save_keypair(keypair: PQCKeypair, out_dir: Path | str) -> tuple[Path, Path]:
    """Save keypair to JSON files (private key with restricted permissions, public key separate)."""
    dir_path = Path(out_dir)
    dir_path.mkdir(parents=True, exist_ok=True)

    priv_file = dir_path / f"{keypair.stage_id.lower()}_private.json"
    pub_file = dir_path / f"{keypair.stage_id.lower()}_public.json"

    with open(priv_file, "w", encoding="utf-8") as f:
        json.dump(keypair.to_dict(), f, indent=2)

    with open(pub_file, "w", encoding="utf-8") as f:
        json.dump(keypair.public_dict(), f, indent=2)

    return priv_file, pub_file


def load_public_key(pub_file: Path | str) -> tuple[str, str, bytes]:
    """Load public key returning (stage_id, algorithm, public_key_bytes)."""
    path = Path(pub_file)
    if not path.exists():
        raise CryptoError(f"Public key file not found: {path}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    stage_id = data.get("stage_id", "UNKNOWN")
    algorithm = data.get("algorithm", "ML-DSA-65")
    pk_hex = data.get("public_key_hex", "")
    if not pk_hex:
        raise MalformedKeyError("Missing 'public_key_hex' in public key file")

    return stage_id, algorithm, bytes.fromhex(pk_hex)


def load_secret_key(priv_file: Path | str) -> tuple[str, str, bytes]:
    """Load secret key returning (stage_id, algorithm, secret_key_bytes)."""
    path = Path(priv_file)
    if not path.exists():
        raise CryptoError(f"Private key file not found: {path}")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    stage_id = data.get("stage_id", "UNKNOWN")
    algorithm = data.get("algorithm", "ML-DSA-65")
    sk_hex = data.get("secret_key_hex", "")
    if not sk_hex:
        raise MalformedKeyError("Missing 'secret_key_hex' in private key file")

    return stage_id, algorithm, bytes.fromhex(sk_hex)


def generate_all_system_keys(
    out_dir: Path | str, algorithm: str = "ML-DSA-65"
) -> dict[str, PQCKeypair]:
    """Generate all cryptographic keys for BootSentry stages and attestation."""
    stages = ["S0", "S1", "S2", "S3", "ATTEST"]
    keypairs = {}
    for st in stages:
        kp = generate_stage_keypair(st, algorithm=algorithm)
        save_keypair(kp, out_dir)
        keypairs[st] = kp
    return keypairs


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate BootSentry PQC Keypairs")
    parser.add_argument("--out-dir", type=str, default="config/keys", help="Output directory")
    parser.add_argument(
        "--algorithm", type=str, default="ML-DSA-65", help="PQC Signature Algorithm"
    )
    args = parser.parse_args()

    print(f"[*] Generating {args.algorithm} keys for all boot stages into {args.out_dir}...")
    kps = generate_all_system_keys(args.out_dir, algorithm=args.algorithm)
    for st, kp in kps.items():
        print(f"  [+] Stage {st:6s}: PK={len(kp.public_key_bytes)} bytes, SK={len(kp.secret_key_bytes)} bytes")
    print("[OK] All PQC keypairs generated successfully.")


if __name__ == "__main__":
    main()
