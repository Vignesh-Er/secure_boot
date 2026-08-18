"""Unit tests for single-source-of-truth evidence generation (evidence.py)."""

from unittest.mock import MagicMock, patch

from bootsentry.eval.evidence import (
    generate_project_metrics,
    get_coverage_percent,
    get_git_commit,
    get_ruff_error_count,
    get_test_count,
)


class TestEvidenceGenerator:
    def test_get_git_commit(self):
        commit = get_git_commit()
        assert isinstance(commit, str)
        assert len(commit) >= 7

    def test_get_test_count(self):
        mock_res = MagicMock(stdout="collected 115 items\n", returncode=0)
        with patch("subprocess.run", return_value=mock_res):
            count, failures = get_test_count()
            assert count == 115
            assert failures == 0

    def test_get_ruff_error_count(self):
        mock_res = MagicMock(stdout="All checks passed!\n", returncode=0)
        with patch("subprocess.run", return_value=mock_res):
            errors = get_ruff_error_count()
            assert errors == 0

    def test_get_coverage_percent(self):
        mock_res = MagicMock(stdout="TOTAL 2500 400 84%\n", returncode=0)
        with patch("subprocess.run", return_value=mock_res):
            cov = get_coverage_percent()
            assert cov == 84

    def test_generate_project_metrics(self, tmp_path):
        out_file = tmp_path / "project_metrics.json"
        with (
            patch("bootsentry.eval.evidence.get_test_count", return_value=(115, 0)),
            patch("bootsentry.eval.evidence.get_coverage_percent", return_value=85),
            patch("bootsentry.eval.evidence.get_ruff_error_count", return_value=0),
            patch("bootsentry.eval.evidence.get_git_commit", return_value="abcdef1"),
        ):
            metrics = generate_project_metrics(eval_dir=tmp_path, out_file=out_file)

        assert out_file.exists()
        assert metrics["project_name"] == "BootSentry"
        assert metrics["test_count"] >= 90
        assert metrics["ruff_errors"] == 0
        assert metrics["security_invariants_verified"] == 8
