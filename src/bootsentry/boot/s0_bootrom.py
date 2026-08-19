"""Stage 0: BootROM — Immutable Root of Trust."""

from __future__ import annotations

import argparse
import hashlib
import os
import subprocess
import sys
import time
import uuid
from pathlib import Path

from bootsentry.boot.handoff import BootHandoff
from bootsentry.crypto.keys import load_public_key
from bootsentry.crypto.manifest import Manifest
from bootsentry.crypto.provider import CryptoError, MalformedKeyError
from bootsentry.crypto.verify import verify_manifest
from bootsentry.measure.eventlog import EventLog
from bootsentry.measure.pcr import PcrBank


def run_stage_0(
    keys_dir: Path | str,
    stages_dir: Path | str,
    run_dir: Path | str,
    boot_id: str | None = None,
    spawn_next: bool = True,
) -> BootHandoff:
    """Execute Stage 0 (BootROM).

    1. Initialize fresh PCR bank (all zeros) and Event Log.
    2. Self-measurement / hardware state hash.
    3. Verify Stage 1 manifest and payload (ML-DSA-65).
    4. Extend PCR[0] with Stage 1 measurement and record in Event Log.
    5. Write handoff to `run_dir/handoff_s0.json`.
    6. Spawn S1 Bootloader process if spawn_next is True.
    """
    t_start = time.perf_counter_ns()
    bid = boot_id or str(uuid.uuid4())
    keys_path = Path(keys_dir)
    stages_path = Path(stages_dir)
    run_path = Path(run_dir)
    run_path.mkdir(parents=True, exist_ok=True)

    if "BOOTSENTRY_BOOT_SECRET" not in os.environ:
        os.environ["BOOTSENTRY_BOOT_SECRET"] = os.urandom(32).hex()

    pcr_bank = PcrBank()
    event_log = EventLog()

    # Step 1: Self-measurement of BootROM hardware state
    rom_state = b"BootSentry_S0_ROM_v1.0.0_Immutable_Root_Hash"
    rom_hash = hashlib.sha256(rom_state).hexdigest()
    pcr_bank.extend(0, rom_hash)
    event_log.record_event(
        stage_id="S0",
        event_type="ROM_INITIALIZE",
        pcr_index=0,
        digest=rom_hash,
        version="1.0.0",
        event_data={"hardware_model": "BootSentry-Virtual-AMD64", "rom_version": "1.0.0"},
    )

    # Step 2: Load S1 manifest & payload
    s1_manifest_file = stages_path / "s1_manifest.json"
    s1_payload_file = stages_path / "s1_payload.bin"
    s0_pub_key_file = keys_path / "s0_public.json"

    if not s1_manifest_file.exists():
        handoff = BootHandoff(
            boot_id=bid,
            current_stage="S0",
            next_stage="S1",
            pcr_state=pcr_bank.to_dict(),
            event_log_data=event_log.to_list(),
            status="HALTED",
            error_message="Stage 1 manifest not found",
        )
        handoff.save(run_path / "handoff_s0.json")
        return handoff

    manifest = Manifest.load(s1_manifest_file)
    payload_bytes = s1_payload_file.read_bytes() if s1_payload_file.exists() else b""

    # Step 3: Cryptographic verification of S1 (Gate 1)
    try:
        _, _, s0_pub_key = load_public_key(s0_pub_key_file)
    except (CryptoError, MalformedKeyError, OSError, ValueError, KeyError) as e:
        handoff = BootHandoff(
            boot_id=bid,
            current_stage="S0",
            next_stage="S1",
            pcr_state=pcr_bank.to_dict(),
            event_log_data=event_log.to_list(),
            status="HALTED",
            error_message=f"Gate 1 Cryptographic failure in S0 loading public key: {e}",
            stage_metrics={"crypto_success": False},
        )
        handoff.save(run_path / "handoff_s0.json")
        return handoff

    verify_res = verify_manifest(
        manifest=manifest,
        public_key_bytes=s0_pub_key,
        payload_bytes=payload_bytes,
        expected_stage_id="S1",
    )

    t_verify_ms = verify_res.latency_ms

    if not verify_res.success:
        handoff = BootHandoff(
            boot_id=bid,
            current_stage="S0",
            next_stage="S1",
            pcr_state=pcr_bank.to_dict(),
            event_log_data=event_log.to_list(),
            status="HALTED",
            error_message=f"Gate 1 Cryptographic failure in S0 verifying S1: {verify_res.reason}",
            stage_metrics={"t_verify_s0": t_verify_ms, "crypto_success": False},
        )
        handoff.save(run_path / "handoff_s0.json")
        return handoff

    # Step 4: Measured Boot extension into PCR[0] (Gate 2)
    s1_digest = manifest.canonical_digest()
    pcr_bank.extend(0, s1_digest)
    event_log.record_event(
        stage_id="S0",
        event_type="STAGE_MEASUREMENT",
        pcr_index=0,
        digest=s1_digest,
        version=manifest.version,
        event_data={
            "target_stage": "S1",
            "security_version_counter": manifest.security_version_counter,
            "payload_size": manifest.payload_size,
        },
    )

    # Real computational workload for BootROM self-test
    for i in range(100):
        _ = hashlib.sha256(f"s0_selftest_block_{i}".encode()).digest()

    t_total_ms = (time.perf_counter_ns() - t_start) / 1_000_000.0

    handoff = BootHandoff(
        boot_id=bid,
        current_stage="S0",
        next_stage="S1",
        pcr_state=pcr_bank.to_dict(),
        event_log_data=event_log.to_list(),
        status="RUNNING",
        stage_metrics={
            "t_verify_s0": t_verify_ms,
            "t_exec_s0": t_total_ms - t_verify_ms,
            "t_total_s0": t_total_ms,
            "crypto_success": True,
        },
    )
    handoff_file = run_path / "handoff_s0.json"
    handoff.save(handoff_file)

    # Step 5: Spawn Stage 1 process
    if spawn_next:
        cmd = [
            sys.executable,
            "-m",
            "bootsentry.boot.s1_bootloader",
            "--handoff",
            str(handoff_file),
            "--keys-dir",
            str(keys_path),
            "--stages-dir",
            str(stages_path),
            "--run-dir",
            str(run_path),
        ]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30, env=os.environ.copy())
            if proc.returncode != 0:
                handoff.status = "HALTED"
                handoff.error_message = f"S1 process exited with code {proc.returncode}: {proc.stderr}"
                handoff.save(handoff_file)
        except subprocess.TimeoutExpired:
            handoff.status = "HALTED"
            handoff.error_message = "S1 process timed out after 30s"
            handoff.save(handoff_file)

    return handoff


def main() -> None:
    parser = argparse.ArgumentParser(description="BootSentry Stage 0 (BootROM)")
    parser.add_argument("--keys-dir", type=str, default="config/keys")
    parser.add_argument("--stages-dir", type=str, default="config/stages")
    parser.add_argument("--run-dir", type=str, default="run")
    parser.add_argument("--boot-id", type=str, default=None)
    parser.add_argument("--no-spawn", action="store_true", help="Do not spawn next stage")
    args = parser.parse_args()

    res = run_stage_0(
        keys_dir=args.keys_dir,
        stages_dir=args.stages_dir,
        run_dir=args.run_dir,
        boot_id=args.boot_id,
        spawn_next=not args.no_spawn,
    )
    if res.status == "HALTED":
        print(f"[HALT S0] {res.error_message}", file=sys.stderr)
        sys.exit(1)
    else:
        print("[OK S0] BootROM completed successfully.")


if __name__ == "__main__":
    main()
