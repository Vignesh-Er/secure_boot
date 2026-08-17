"""High-level boot chain orchestrator and execution runner."""

from __future__ import annotations

import argparse
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from bootsentry.boot.handoff import BootHandoff
from bootsentry.boot.s0_bootrom import run_stage_0
from bootsentry.crypto.keys import generate_all_system_keys
from bootsentry.crypto.manifest import Manifest, compute_payload_sha256
from bootsentry.crypto.sign import sign_manifest
from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank
from bootsentry.measure.quote import AttestationQuote


@dataclass
class BootExecutionResult:
    boot_id: str
    status: str  # "COMPLETED" or "HALTED"
    error_message: str | None
    pcr_bank: PcrBank
    event_log: EventLog
    quote: AttestationQuote | None
    stage_metrics: dict[str, Any]
    total_boot_time_ms: float
    handoff: BootHandoff

    def to_dict(self) -> dict[str, Any]:
        return {
            "boot_id": self.boot_id,
            "status": self.status,
            "error_message": self.error_message,
            "pcr_bank": self.pcr_bank.to_dict(),
            "event_log_count": len(self.event_log.entries),
            "quote_present": self.quote is not None,
            "stage_metrics": self.stage_metrics,
            "total_boot_time_ms": self.total_boot_time_ms,
        }


def initialize_default_environment(
    base_dir: Path | str = ".",
    default_algorithm: str = "ML-DSA-65",
) -> tuple[Path, Path]:
    """Ensure standard keys and signed stage manifests exist for clean boot."""
    base = Path(base_dir)
    keys_dir = base / "config" / "keys"
    stages_dir = base / "config" / "stages"

    keys_dir.mkdir(parents=True, exist_ok=True)
    stages_dir.mkdir(parents=True, exist_ok=True)

    # 1. Generate keys if not present
    if not (keys_dir / "s0_public.json").exists():
        generate_all_system_keys(keys_dir, algorithm=default_algorithm)

    # 2. Generate and sign standard stages S1, S2, S3
    stage_configs = [
        ("s1", "S1", "1.4.0", 5, b"# Bootloader S1 binary payload\nprint('S1 Bootloader starting...')"),
        ("s2", "S2", "6.1.0", 5, b"# Kernel S2 image payload\nprint('S2 Kernel booting...')"),
        ("s3", "S3", "1.0.0", 5, b"# Init S3 system payload\nprint('S3 Init running...')"),
    ]

    for prefix, stage_id, ver, svn, payload_bytes in stage_configs:
        payload_file = stages_dir / f"{prefix}_payload.bin"
        if not payload_file.exists():
            payload_file.write_bytes(payload_bytes)

        manifest_file = stages_dir / f"{prefix}_manifest.json"
        if not manifest_file.exists():
            digest, size = compute_payload_sha256(payload_bytes)
            # Stage S1 is signed by S0 key, S2 by S1 key, S3 by S2 key
            signer_stage = "s0" if stage_id == "S1" else ("s1" if stage_id == "S2" else "s2")
            signer_key_file = keys_dir / f"{signer_stage}_private.json"

            from bootsentry.crypto.keys import load_secret_key

            _, _, sk_bytes = load_secret_key(signer_key_file)

            m = Manifest(
                stage_id=stage_id,
                version=ver,
                security_version_counter=svn,
                algorithm=default_algorithm,
                payload_sha256=digest,
                payload_size=size,
                expected_pcr="0" * 64,
                metadata={"description": f"Standard {stage_id} component"},
            )
            signed_m = sign_manifest(m, sk_bytes, algorithm=default_algorithm)
            signed_m.save(manifest_file)


    return keys_dir, stages_dir


def execute_boot_chain(
    keys_dir: Path | str = "config/keys",
    stages_dir: Path | str = "config/stages",
    run_dir: Path | str = "run",
    boot_id: str | None = None,
    service_sequence: list[str] | None = None,
) -> BootExecutionResult:
    """Execute the complete 4-stage boot chain (S0 -> S1 -> S2 -> S3)."""
    t0 = time.perf_counter_ns()
    bid = boot_id or str(uuid.uuid4())
    run_path = Path(run_dir) / bid
    run_path.mkdir(parents=True, exist_ok=True)

    # Stage 0: BootROM
    h0 = run_stage_0(
        keys_dir=keys_dir,
        stages_dir=stages_dir,
        run_dir=run_path,
        boot_id=bid,
        spawn_next=False,
    )

    if h0.status == "HALTED":
        total_time_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return BootExecutionResult(
            boot_id=bid,
            status="HALTED",
            error_message=h0.error_message,
            pcr_bank=h0.get_pcr_bank(),
            event_log=h0.get_event_log(),
            quote=None,
            stage_metrics=h0.stage_metrics,
            total_boot_time_ms=total_time_ms,
            handoff=h0,
        )

    # Stage 1: Bootloader
    from bootsentry.boot.s1_bootloader import run_stage_1

    h1 = run_stage_1(
        handoff_path=run_path / "handoff_s0.json",
        keys_dir=keys_dir,
        stages_dir=stages_dir,
        run_dir=run_path,
        spawn_next=False,
    )

    if h1.status == "HALTED":
        total_time_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return BootExecutionResult(
            boot_id=bid,
            status="HALTED",
            error_message=h1.error_message,
            pcr_bank=h1.get_pcr_bank(),
            event_log=h1.get_event_log(),
            quote=None,
            stage_metrics=h1.stage_metrics,
            total_boot_time_ms=total_time_ms,
            handoff=h1,
        )

    # Stage 2: Kernel
    from bootsentry.boot.s2_kernel import run_stage_2

    h2 = run_stage_2(
        handoff_path=run_path / "handoff_s1.json",
        keys_dir=keys_dir,
        stages_dir=stages_dir,
        run_dir=run_path,
        spawn_next=False,
    )

    if h2.status == "HALTED":
        total_time_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
        return BootExecutionResult(
            boot_id=bid,
            status="HALTED",
            error_message=h2.error_message,
            pcr_bank=h2.get_pcr_bank(),
            event_log=h2.get_event_log(),
            quote=None,
            stage_metrics=h2.stage_metrics,
            total_boot_time_ms=total_time_ms,
            handoff=h2,
        )

    # Stage 3: Init & Services
    from bootsentry.boot.s3_init import run_stage_3

    h3 = run_stage_3(
        handoff_path=run_path / "handoff_s2.json",
        keys_dir=keys_dir,
        stages_dir=stages_dir,
        run_dir=run_path,
        service_sequence=service_sequence,
    )

    total_time_ms = (time.perf_counter_ns() - t0) / 1_000_000.0
    quote = AttestationQuote.from_dict(h3.quote_data) if h3.quote_data else None

    # Merge all stage metrics
    all_metrics = {}
    for h in [h0, h1, h2, h3]:
        all_metrics.update(h.stage_metrics)

    return BootExecutionResult(
        boot_id=bid,
        status=h3.status,
        error_message=h3.error_message,
        pcr_bank=h3.get_pcr_bank(),
        event_log=h3.get_event_log(),
        quote=quote,
        stage_metrics=all_metrics,
        total_boot_time_ms=total_time_ms,
        handoff=h3,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description="BootSentry Boot Runner")
    parser.add_argument("--keys-dir", type=str, default="config/keys")
    parser.add_argument("--stages-dir", type=str, default="config/stages")
    parser.add_argument("--run-dir", type=str, default="run")
    parser.add_argument("--init-env", action="store_true", help="Initialize keys and manifests")
    args = parser.parse_args()

    if args.init_env or not Path(args.keys_dir).exists():
        print("[*] Initializing BootSentry crypto keys and stage manifests...")
        initialize_default_environment()

    print("[*] Starting BootSentry 4-Stage Secure Boot Execution...")
    res = execute_boot_chain(
        keys_dir=args.keys_dir,
        stages_dir=args.stages_dir,
        run_dir=args.run_dir,
    )

    print("-" * 60)
    print(f"Boot ID:       {res.boot_id}")
    print(f"Status:        {res.status}")
    print(f"Total Time:    {res.total_boot_time_ms:.2f} ms")
    print(f"Event Count:   {len(res.event_log.entries)}")
    print(f"PCR0:          {res.pcr_bank.read(0)[:24]}...")
    print(f"PCR1:          {res.pcr_bank.read(1)[:24]}...")
    print(f"PCR2:          {res.pcr_bank.read(2)[:24]}...")
    print(f"PCR3:          {res.pcr_bank.read(3)[:24]}...")
    if res.quote:
        print(f"Attestation:   Signed ML-DSA-65 Quote Present (Nonce={res.quote.nonce[:8]}...)")
    if res.error_message:
        print(f"Error:         {res.error_message}")
    print("-" * 60)


if __name__ == "__main__":
    main()
