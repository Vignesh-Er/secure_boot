"""Stage 1: Bootloader — Hardware Initialization & Kernel Verification."""

from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from bootsentry.boot.handoff import BootHandoff
from bootsentry.crypto.keys import load_public_key
from bootsentry.crypto.manifest import Manifest
from bootsentry.crypto.verify import verify_manifest


def run_stage_1(
    handoff_path: Path | str,
    keys_dir: Path | str,
    stages_dir: Path | str,
    run_dir: Path | str,
    spawn_next: bool = True,
) -> BootHandoff:
    """Execute Stage 1 (Bootloader).

    1. Ingest S0 handoff.
    2. Execute bootloader memory init & device tree synthesis.
    3. Verify Stage 2 (Kernel) manifest and payload (ML-DSA-65).
    4. Extend PCR[1] with Stage 2 measurement and record in Event Log.
    5. Write handoff to `run_dir/handoff_s1.json`.
    6. Spawn S2 Kernel process if spawn_next is True.
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

    # Step 1: Real computational workload (Memory setup & Device Tree table)
    dt_entries = {}
    hasher = hashlib.sha256()
    for node_id in range(120):
        dt_node = {
            "node": f"soc/peripheral_{node_id}",
            "reg": [0x10000000 + node_id * 0x1000, 0x1000],
            "interrupts": [node_id % 32],
        }
        b = json.dumps(dt_node, sort_keys=True).encode()
        h = hashlib.sha256(b).hexdigest()
        hasher.update(h.encode())
        dt_entries[node_id] = h[:8]

    dt_digest = hasher.hexdigest()
    pcr_bank.extend(1, dt_digest)
    event_log.record_event(
        stage_id="S1",
        event_type="DEVICE_TREE_LOAD",
        pcr_index=1,
        digest=dt_digest,
        version="1.0.0",
        event_data={"nodes_parsed": len(dt_entries), "dtb_hash": dt_digest[:16]},
    )

    # Step 2: Load S2 manifest & payload
    s2_manifest_file = stages_path / "s2_manifest.json"
    s2_payload_file = stages_path / "s2_payload.bin"
    s1_pub_key_file = keys_path / "s1_public.json"

    if not s2_manifest_file.exists():
        handoff.current_stage = "S1"
        handoff.next_stage = "S2"
        handoff.status = "HALTED"
        handoff.error_message = "Stage 2 Kernel manifest not found"
        handoff.save(run_path / "handoff_s1.json")
        return handoff

    manifest = Manifest.load(s2_manifest_file)
    payload_bytes = s2_payload_file.read_bytes() if s2_payload_file.exists() else b""

    # Step 3: Cryptographic verification of S2 Kernel (Gate 1)
    _, _, s1_pub_key = load_public_key(s1_pub_key_file)
    verify_res = verify_manifest(
        manifest=manifest,
        public_key_bytes=s1_pub_key,
        payload_bytes=payload_bytes,
        expected_stage_id="S2",
    )

    t_verify_ms = verify_res.latency_ms

    if not verify_res.success:
        handoff.current_stage = "S1"
        handoff.next_stage = "S2"
        handoff.status = "HALTED"
        handoff.error_message = f"Gate 1 Cryptographic failure in S1 verifying S2: {verify_res.reason}"
        handoff.stage_metrics["t_verify_s1"] = t_verify_ms
        handoff.stage_metrics["crypto_success_s1"] = False
        handoff.save(run_path / "handoff_s1.json")
        return handoff

    # Step 4: Measured Boot extension into PCR[1] (Gate 2)
    s2_digest = manifest.canonical_digest()
    pcr_bank.extend(1, s2_digest)
    event_log.record_event(
        stage_id="S1",
        event_type="STAGE_MEASUREMENT",
        pcr_index=1,
        digest=s2_digest,
        version=manifest.version,
        event_data={
            "target_stage": "S2",
            "security_version_counter": manifest.security_version_counter,
            "payload_size": manifest.payload_size,
        },
    )

    t_total_ms = (time.perf_counter_ns() - t_start) / 1_000_000.0

    handoff.current_stage = "S1"
    handoff.next_stage = "S2"
    handoff.pcr_state = pcr_bank.to_dict()
    handoff.event_log_data = event_log.to_list()
    handoff.stage_metrics["t_verify_s1"] = t_verify_ms
    handoff.stage_metrics["t_exec_s1"] = t_total_ms - t_verify_ms
    handoff.stage_metrics["t_total_s1"] = t_total_ms
    handoff.stage_metrics["crypto_success_s1"] = True

    out_file = run_path / "handoff_s1.json"
    handoff.save(out_file)

    # Step 5: Spawn Stage 2 process
    if spawn_next:
        cmd = [
            sys.executable,
            "-m",
            "bootsentry.boot.s2_kernel",
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
            handoff.error_message = f"S2 process exited with code {proc.returncode}: {proc.stderr}"
            handoff.save(out_file)

    return handoff


def main() -> None:
    parser = argparse.ArgumentParser(description="BootSentry Stage 1 (Bootloader)")
    parser.add_argument("--handoff", type=str, required=True)
    parser.add_argument("--keys-dir", type=str, default="config/keys")
    parser.add_argument("--stages-dir", type=str, default="config/stages")
    parser.add_argument("--run-dir", type=str, default="run")
    parser.add_argument("--no-spawn", action="store_true")
    args = parser.parse_args()

    res = run_stage_1(
        handoff_path=args.handoff,
        keys_dir=args.keys_dir,
        stages_dir=args.stages_dir,
        run_dir=args.run_dir,
        spawn_next=not args.no_spawn,
    )
    if res.status == "HALTED":
        print(f"[HALT S1] {res.error_message}", file=sys.stderr)
        sys.exit(1)
    else:
        print("[OK S1] Bootloader completed successfully.")


if __name__ == "__main__":
    main()
