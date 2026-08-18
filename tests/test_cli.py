"""Unit tests for the BootSentry CLI dispatcher."""

import sys
from unittest.mock import patch

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

    def test_cli_version(self, capsys):
        with patch.object(sys, "argv", ["bootsentry", "version"]):
            main()
        captured = capsys.readouterr()
        assert "BootSentry v1.0.0" in captured.out

    def test_cli_boot_subcommand(self, tmp_path):
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

    def test_cli_keys_subcommand(self, tmp_path):
        out_dir = tmp_path / "keys"
        with patch.object(
            sys, "argv", ["bootsentry", "keys", "--out-dir", str(out_dir), "--algorithm", "ML-DSA-65"]
        ):
            main()
        assert (out_dir / "s0_public.json").exists()
