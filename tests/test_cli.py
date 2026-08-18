"""Unit tests for the BootSentry CLI dispatcher."""

import sys
from unittest.mock import MagicMock, patch

import pytest

from bootsentry.cli import main


class TestCLI:
    def test_cli_help(self, capsys):
        with patch.object(sys, "argv", ["bootsentry", "--help"]):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 0
        captured = capsys.readouterr()
        assert "BootSentry: AI-Assisted Secure Boot" in captured.out

    def test_cli_no_args_shows_help(self, capsys):
        with patch.object(sys, "argv", ["bootsentry"]):
            main()
        captured = capsys.readouterr()
        assert "usage: bootsentry" in captured.out

    def test_cli_version(self, capsys):
        with patch.object(sys, "argv", ["bootsentry", "version"]):
            main()
        captured = capsys.readouterr()
        assert "BootSentry v1.0.0" in captured.out

    def test_cli_boot_subcommand(self, tmp_path, capsys):
        from bootsentry.boot.runner import initialize_default_environment

        keys_dir, stages_dir = initialize_default_environment(base_dir=tmp_path)
        run_dir = tmp_path / "run"

        with patch.object(
            sys,
            "argv",
            [
                "bootsentry",
                "boot",
                "--keys-dir",
                str(keys_dir),
                "--stages-dir",
                str(stages_dir),
                "--run-dir",
                str(run_dir),
            ],
        ):
            main()

        captured = capsys.readouterr()
        assert "Status: COMPLETED" in captured.out
        assert "Boot ID:" in captured.out
        boot_dirs = list(run_dir.glob("*"))
        assert len(boot_dirs) >= 1
        assert (boot_dirs[0] / "handoff_s3.json").exists()

    def test_cli_boot_halt_exits_code_1(self, tmp_path):
        from bootsentry.boot.runner import initialize_default_environment

        keys_dir, stages_dir = initialize_default_environment(base_dir=tmp_path)
        (stages_dir / "s1_payload.bin").write_bytes(b"TAMPERED")
        run_dir = tmp_path / "run"

        with patch.object(
            sys,
            "argv",
            [
                "bootsentry",
                "boot",
                "--keys-dir",
                str(keys_dir),
                "--stages-dir",
                str(stages_dir),
                "--run-dir",
                str(run_dir),
            ],
        ):
            with pytest.raises(SystemExit) as exc:
                main()
            assert exc.value.code == 1

    def test_cli_keys_subcommand(self, tmp_path, capsys):
        out_dir = tmp_path / "keys"
        with patch.object(
            sys,
            "argv",
            ["bootsentry", "keys", "--out-dir", str(out_dir), "--algorithm", "ML-DSA-65"],
        ):
            main()
        captured = capsys.readouterr()
        assert "[OK] Generated ML-DSA-65 keys" in captured.out
        assert (out_dir / "s0_public.json").exists()
        assert (out_dir / "s1_public.json").exists()
        assert (out_dir / "s2_public.json").exists()
        assert (out_dir / "s3_public.json").exists()
        assert (out_dir / "attest_public.json").exists()

    def test_cli_sign_subcommand(self, tmp_path, capsys):
        from bootsentry.boot.runner import initialize_default_environment

        keys_dir, stages_dir = initialize_default_environment(base_dir=tmp_path)
        with patch.object(
            sys,
            "argv",
            [
                "bootsentry",
                "sign",
                "--keys-dir",
                str(keys_dir),
                "--stages-dir",
                str(stages_dir),
            ],
        ):
            main()
        captured = capsys.readouterr()
        assert "[OK] Signed S1" in captured.out
        assert "[OK] Signed S2" in captured.out
        assert "[OK] Signed S3" in captured.out

    def test_cli_demo_subcommand(self, capsys):
        with patch.object(
            sys,
            "argv",
            ["bootsentry", "demo", "--scenario", "clean"],
        ):
            main()
        captured = capsys.readouterr()
        assert "VERDICT: PASS" in captured.out

    def test_cli_attack_subcommand(self):
        mock_attack = MagicMock()
        with (
            patch.object(sys, "argv", ["bootsentry", "attack", "--all"]),
            patch("bootsentry.attacks.runner.main", mock_attack),
        ):
            main()
        mock_attack.assert_called_once()

    def test_cli_collect_subcommand(self):
        mock_collect = MagicMock()
        with (
            patch.object(sys, "argv", ["bootsentry", "collect", "--count", "5"]),
            patch("bootsentry.eval.collector.main", mock_collect),
        ):
            main()
        mock_collect.assert_called_once()

    def test_cli_train_subcommand(self):
        mock_train = MagicMock()
        with (
            patch.object(sys, "argv", ["bootsentry", "train", "--models-dir", "models"]),
            patch("bootsentry.eval.trainer.main", mock_train),
        ):
            main()
        mock_train.assert_called_once()

    def test_cli_eval_subcommand(self):
        mock_eval = MagicMock()
        with (
            patch.object(sys, "argv", ["bootsentry", "eval", "--out-dir", "eval"]),
            patch("bootsentry.eval.evaluate.main", mock_eval),
        ):
            main()
        mock_eval.assert_called_once()

    def test_cli_judge_check_subcommand(self):
        mock_judge = MagicMock()
        with (
            patch.object(sys, "argv", ["bootsentry", "judge-check"]),
            patch("bootsentry.eval.judge_check.main", mock_judge),
        ):
            main()
        mock_judge.assert_called_once()
