"""Unified CLI entry point for BootSentry."""

from __future__ import annotations

import argparse
import sys


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="bootsentry",
        description="BootSentry: AI-Assisted Secure Boot & Post-Quantum Integrity Verification",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: boot
    boot_parser = subparsers.add_parser("boot", help="Execute 4-stage secure boot flow")
    boot_parser.add_argument("--keys-dir", type=str, default="config/keys", help="Keys directory")
    boot_parser.add_argument(
        "--stages-dir", type=str, default="config/stages", help="Stages directory"
    )
    boot_parser.add_argument("--run-dir", type=str, default="run", help="Run directory")

    # Command: keys
    keys_parser = subparsers.add_parser("keys", help="Generate Post-Quantum cryptographic keys")
    keys_parser.add_argument("--out-dir", type=str, default="config/keys", help="Output directory")
    keys_parser.add_argument(
        "--algorithm",
        type=str,
        default="ML-DSA-65",
        help="PQC algorithm (ML-DSA-65, ML-DSA-44, ML-DSA-87)",
    )

    # Command: sign
    subparsers.add_parser("sign", help="Sign boot stage manifests with PQC")

    # Command: demo
    subparsers.add_parser("demo", help="Run Rich TUI interactive dashboard")

    # Command: attack
    subparsers.add_parser("attack", help="Execute attack scenarios testbed")

    # Command: collect
    collect_parser = subparsers.add_parser("collect", help="Collect genuine process boot telemetry")
    collect_parser.add_argument("--count", type=int, default=100, help="Number of boots to record")
    collect_parser.add_argument(
        "--out-dir", type=str, default="data/telemetry", help="Output directory"
    )

    # Command: train
    train_parser = subparsers.add_parser(
        "train", help="Train and seal Gate 3 anomaly detection models"
    )
    train_parser.add_argument(
        "--data-file", type=str, default="data/telemetry/normal_boots.jsonl", help="Dataset file"
    )
    train_parser.add_argument(
        "--models-dir", type=str, default="models", help="Models output directory"
    )

    # Command: eval
    subparsers.add_parser("eval", help="Run comprehensive evaluation")

    # Command: judge-check
    subparsers.add_parser("judge-check", help="Run 14-point automated judge verification")

    # Command: version
    subparsers.add_parser("version", help="Print BootSentry version")

    args, remaining = parser.parse_known_args()

    if args.command == "boot":
        from bootsentry.boot.runner import execute_boot_chain

        res = execute_boot_chain(
            keys_dir=args.keys_dir,
            stages_dir=args.stages_dir,
            run_dir=args.run_dir,
        )
        print(
            f"Boot ID: {res.boot_id} | Status: {res.status} | Time: {res.total_boot_time_ms:.2f} ms"
        )
        if res.status != "COMPLETED":
            sys.exit(1)

    elif args.command == "keys":
        from bootsentry.crypto.keys import generate_all_system_keys

        generate_all_system_keys(out_dir=args.out_dir, algorithm=args.algorithm)
        print(f"[OK] Generated {args.algorithm} keys in {args.out_dir}")

    elif args.command == "sign":
        from bootsentry.crypto.sign import main as sign_main

        sys.argv = [sys.argv[0]] + remaining
        sign_main()

    elif args.command == "demo":
        from bootsentry.demo.tui import main as demo_main

        sys.argv = [sys.argv[0]] + remaining
        demo_main()

    elif args.command == "attack":
        from bootsentry.attacks.runner import main as attack_main

        sys.argv = [sys.argv[0]] + remaining
        attack_main()

    elif args.command == "collect":
        from bootsentry.eval.collector import main as collect_main

        sys.argv = [sys.argv[0]] + remaining
        collect_main()

    elif args.command == "train":
        from bootsentry.eval.trainer import main as train_main

        sys.argv = [sys.argv[0]] + remaining
        train_main()

    elif args.command == "eval":
        from bootsentry.eval.evaluate import main as eval_main

        sys.argv = [sys.argv[0]] + remaining
        eval_main()

    elif args.command == "judge-check":
        from bootsentry.eval.judge_check import main as judge_main

        sys.argv = [sys.argv[0]] + remaining
        judge_main()

    elif args.command == "version":
        print("BootSentry v1.0.0 (Post-Quantum AI Secure Boot)")

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
