"""Stage 2: Kernel — Subsystem Initialization & Init Verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from bootsentry.boot.handoff import BootHandoff
from bootsentry.crypto.keys import load_public_key
from bootsentry.crypto.manifest import Manifest
from bootsentry.crypto.verify import verify_manifest


def run_stage_2(
    handoff_path: Path | str,
    keys_dir: Path | str,
    stages_dir: Path | str,
    run_dir: Path | str,
    spawn_next: bool = True,
) -> BootHandoff:
    """Execute Stage 2 (Kernel).

    1. Ingest S1 handoff.
    2. Initialize kernel scheduler tables, memory structures, and security subsystem.
    3. Verify Stage 3 (Init) manifest and payload (ML-DSA-65).
    4. Extend PCR[2] with Stage 3 measurement and record in Event Log.
    5. Write handoff to `run_dir/handoff_s2.json`.
    6. Spawn S3 Init process if spawn_next is True.
    """
    t_start = time.perf_counter_ns()
    keys_path = Path(keys_dir)
    stages_path = Path(stages_dir)
    run_path = Path(run_dir)

    handoff = BootHandoff.load(handoff_path)
    if handoff.status == "HALTED":
        return handoff

    pcr_bank = handoff.get_pcr_bank()
    event_log = handoff.get_event_log()

    # Step 1: Real computational kernel initialization workload
    # Simulate page table construction and task descriptor allocation
    tasks = []
    hasher = hashlib.sha256()
    for pid in range(1, 101):
        task_desc = {
            "pid": pid,
            "ppid": 0 if pid == 1 else 1,
            "state": "TASK_RUNNING",
            "priority": 120 - (pid % 20),
            "vm_start": 0x400000 + pid * 0x10000,
            "vm_size": 0x8000,
        }
        b = json.dumps(task_desc, sort_keys=True).encode()
        h = hashlib.sha256(b).hexdigest()
        hasher.update(h.encode())
        tasks.append(h[:6])

    kernel_state_digest = hasher.hexdigest()
    pcr_bank.extend(2, kernel_state_digest)
    event_log.record_event(
        stage_id="S2",
        event_type="KERNEL_INIT",
        pcr_index=2,
        digest=kernel_state_digest,
        version="6.1.0-bootsentry",
        event_data={"tasks_allocated": len(tasks), "kernel_hash": kernel_state_digest[:16]},
    )

    # Step 2: Load S3 manifest & payload
    s3_manifest_file = stages_path / "s3_manifest.json"
    s3_payload_file = stages_path / "s3_payload.bin"
    s2_pub_key_file = keys_path / "s2_public.json"

    if not s3_manifest_file.exists():
        handoff.current_stage = "S2"
        handoff.next_stage = "S3"
        handoff.status = "HALTED"
        handoff.error_message = "Stage 3 Init manifest not found"
        handoff.save(run_path / "handoff_s2.json")
        return handoff

    manifest = Manifest.load(s3_manifest_file)
    payload_bytes = s3_payload_file.read_bytes() if s3_payload_file.exists() else b""

    # Step 3: Cryptographic verification of S3 Init (Gate 1)
    _, _, s2_pub_key = load_public_key(s2_pub_key_file)
    verify_res = verify_manifest(
        manifest=manifest,
        public_key_bytes=s2_pub_key,
        payload_bytes=payload_bytes,
        expected_stage_id="S3",
    )

    t_verify_ms = verify_res.latency_ms

    if not verify_res.success:
        handoff.current_stage = "S2"
        handoff.next_stage = "S3"
        handoff.status = "HALTED"
        handoff.error_message = f"Gate 1 Cryptographic failure in S2 verifying S3: {verify_res.reason}"
        handoff.stage_metrics["t_verify_s2"] = t_verify_ms
        handoff.stage_metrics["crypto_success_s2"] = False
        handoff.save(run_path / "handoff_s2.json")
        return handoff

    # Step 4: Measured Boot extension into PCR[2] (Gate 2)
    s3_digest = manifest.canonical_digest()
    pcr_bank.extend(2, s3_digest)
    event_log.record_event(
        stage_id="S2",
        event_type="STAGE_MEASUREMENT",
        pcr_index=2,
        digest=s3_digest,
        version=manifest.version,
        event_data={
            "target_stage": "S3",
            "security_version_counter": manifest.security_version_counter,
            "payload_size": manifest.payload_size,
        },
    )

    t_total_ms = (time.perf_counter_ns() - t_start) / 1_000_000.0

    handoff.current_stage = "S2"
    handoff.next_stage = "S3"
    handoff.pcr_state = pcr_bank.to_dict()
    handoff.event_log_data = event_log.to_list()
    handoff.stage_metrics["t_verify_s2"] = t_verify_ms
    handoff.stage_metrics["t_exec_s2"] = t_total_ms - t_verify_ms
    handoff.stage_metrics["t_total_s2"] = t_total_ms
    handoff.stage_metrics["crypto_success_s2"] = True

    out_file = run_path / "handoff_s2.json"
    handoff.save(out_file)

    # Step 5: Spawn Stage 3 process
    if spawn_next:
        cmd = [
            sys.executable,
            "-m",
            "bootsentry.boot.s3_init",
            "--handoff",
            str(out_file),
            "--keys-dir",
            str(keys_path),
            "--stages-dir",
            str(stages_path),
            "--run-dir",
            str(run_path),
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True)
        if proc.returncode != 0:
            handoff.status = "HALTED"
            handoff.error_message = f"S3 process exited with code {proc.returncode}: {proc.stderr}"
            handoff.save(out_file)

    return handoff


def main() -> None:
    parser = argparse.ArgumentParser(description="BootSentry Stage 2 (Kernel)")
    parser.add_argument("--handoff", type=str, required=True)
    parser.add_argument("--keys-dir", type=str, default="config/keys")
    parser.add_argument("--stages-dir", type=str, default="config/stages")
    parser.add_argument("--run-dir", type=str, default="run")
    parser.add_argument("--no-spawn", action="store_true")
    args = parser.parse_args()

    res = run_stage_2(
        handoff_path=args.handoff,
        keys_dir=args.keys_dir,
        stages_dir=args.stages_dir,
        run_dir=args.run_dir,
        spawn_next=not args.no_spawn,
    )
    if res.status == "HALTED":
        print(f"[HALT S2] {res.error_message}", file=sys.stderr)
        sys.exit(1)
    else:
        print("[✓ S2] Kernel completed successfully.")


if __name__ == "__main__":
    main()
