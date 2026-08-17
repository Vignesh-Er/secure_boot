"""Stage 3: Init & Services — Service Orchestration & PQC Attestation Quote."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

from bootsentry.boot.handoff import BootHandoff
from bootsentry.boot.services import DEFAULT_SERVICE_SEQUENCE, SERVICE_REGISTRY
from bootsentry.crypto.keys import load_secret_key
from bootsentry.measure.quote import generate_attestation_quote


def run_stage_3(
    handoff_path: Path | str,
    keys_dir: Path | str,
    stages_dir: Path | str,
    run_dir: Path | str,
    service_sequence: Optional[List[str]] = None,
) -> BootHandoff:
    """Execute Stage 3 (Init).

    1. Ingest S2 handoff.
    2. Launch system services in specified sequence.
    3. Measure each service execution into PCR[3] and log in Event Log.
    4. Generate signed PQC Attestation Quote (ML-DSA-65).
    5. Save final completed handoff state to `run_dir/handoff_s3.json`.
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

    # Step 1: Execute configured service sequence
    seq = service_sequence if service_sequence is not None else DEFAULT_SERVICE_SEQUENCE
    service_results = {}

    for svc_name in seq:
        t_svc_start = time.perf_counter_ns()
        svc_fn = SERVICE_REGISTRY.get(svc_name)
        if not svc_fn:
            handoff.current_stage = "S3"
            handoff.next_stage = "DONE"
            handoff.status = "HALTED"
            handoff.error_message = f"Unknown service requested in S3 init sequence: {svc_name}"
            handoff.save(run_path / "handoff_s3.json")
            return handoff

        # Execute real computational service workload
        res = svc_fn()
        t_svc_ms = (time.perf_counter_ns() - t_svc_start) / 1_000_000.0

        # Measure into PCR[3] and record in Event Log
        pcr_bank.extend(3, res.digest)
        event_log.record_event(
            stage_id="S3",
            event_type="SERVICE_START",
            pcr_index=3,
            digest=res.digest,
            version="1.0.0",
            event_data={"service_name": svc_name, "details": res.details, "latency_ms": t_svc_ms},
        )
        service_results[svc_name] = {
            "status": res.status,
            "digest": res.digest,
            "latency_ms": t_svc_ms,
        }

    # Step 2: Generate Signed Attestation Quote
    attest_key_file = keys_path / "attest_private.json"
    if attest_key_file.exists():
        _, alg, sk_bytes = load_secret_key(attest_key_file)
        quote = generate_attestation_quote(
            pcr_bank=pcr_bank,
            event_log=event_log,
            attestation_secret_key_bytes=sk_bytes,
            boot_id=handoff.boot_id,
            algorithm=alg,
        )
        quote_data = quote.to_dict()
    else:
        quote_data = None

    t_total_ms = (time.perf_counter_ns() - t_start) / 1_000_000.0

    handoff.current_stage = "S3"
    handoff.next_stage = "COMPLETED"
    handoff.status = "COMPLETED"
    handoff.pcr_state = pcr_bank.to_dict()
    handoff.event_log_data = event_log.to_list()
    handoff.quote_data = quote_data
    handoff.stage_metrics["t_total_s3"] = t_total_ms
    handoff.stage_metrics["services"] = service_results

    out_file = run_path / "handoff_s3.json"
    handoff.save(out_file)
    return handoff


def main() -> None:
    parser = argparse.ArgumentParser(description="BootSentry Stage 3 (Init)")
    parser.add_argument("--handoff", type=str, required=True)
    parser.add_argument("--keys-dir", type=str, default="config/keys")
    parser.add_argument("--stages-dir", type=str, default="config/stages")
    parser.add_argument("--run-dir", type=str, default="run")
    parser.add_argument(
        "--services",
        type=str,
        default=None,
        help="Comma-separated service sequence (e.g. svc_a,svc_b,svc_c,svc_attest,svc_e)",
    )
    args = parser.parse_args()

    svc_seq = args.services.split(",") if args.services else None
    res = run_stage_3(
        handoff_path=args.handoff,
        keys_dir=args.keys_dir,
        stages_dir=args.stages_dir,
        run_dir=args.run_dir,
        service_sequence=svc_seq,
    )
    if res.status == "HALTED":
        print(f"[HALT S3] {res.error_message}", file=sys.stderr)
        sys.exit(1)
    else:
        print("[OK S3] Init and services completed successfully.")


if __name__ == "__main__":
    main()
