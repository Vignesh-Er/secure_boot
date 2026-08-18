"""Unit tests for Data Collection, Model Training, and Evaluation."""


import numpy as np
import pytest

from bootsentry.boot.runner import initialize_default_environment
from bootsentry.eval.collector import collect_single_real_boot, run_data_collection
from bootsentry.eval.evaluate import compute_roc_pr_metrics, run_comprehensive_evaluation
from bootsentry.eval.trainer import train_all_models
from bootsentry.telemetry.logger import read_boot_records


@pytest.fixture(scope="module")
def eval_env(tmp_path_factory):
    base_dir = tmp_path_factory.mktemp("eval_base")
    initialize_default_environment(base_dir=base_dir)
    return base_dir


class TestEvaluationPipeline:
    def test_single_boot_collection(self, eval_env, tmp_path):
        keys_dir = eval_env / "config" / "keys"
        stages_dir = eval_env / "config" / "stages"
        run_dir = tmp_path / "run"

        rec = collect_single_real_boot(
            keys_dir=keys_dir,
            stages_dir=stages_dir,
            run_dir=run_dir,
            boot_idx=0,
            background_workload="none",
        )
        assert rec.label == "normal"
        assert rec.crypto_status == "PASS"
        assert rec.total_boot_time_ms > 0.0


    def test_train_and_evaluate_end_to_end(self, eval_env, tmp_path):
        data_dir = tmp_path / "telemetry"
        models_dir = tmp_path / "models"
        eval_out = tmp_path / "eval"

        # 1. Collect sample real boots
        data_file = run_data_collection(count=15, out_dir=data_dir, base_dir=eval_env)
        assert data_file.exists()
        records = read_boot_records(data_file)
        assert len(records) == 15

        # 2. Train models
        model_paths = train_all_models(data_file=data_file, models_dir=models_dir)
        assert len(model_paths) >= 4
        assert (models_dir / "isolation_forest.joblib").exists()
        assert (models_dir / "markov_sequence.joblib").exists()
        assert (models_dir / "ewma_monitor.joblib").exists()
        assert (models_dir / "attribution_engine.joblib").exists()
        assert (models_dir / "model_manifest.json").exists()



        # 3. Run full evaluation
        metrics = run_comprehensive_evaluation(
            models_dir=models_dir,
            data_file=data_file,
            out_dir=eval_out,
            base_dir=eval_env,
        )

        assert "roc_auc" in metrics
        assert "pr_auc" in metrics
        assert metrics["benign_incorrect_halts"] == 0
        assert (eval_out / "report.html").exists()
        assert (eval_out / "metrics.json").exists()

    def test_compute_roc_pr_metrics(self):
        y_true = np.array([0, 0, 0, 0, 1, 1, 1, 1])
        y_scores = np.array([0.1, 0.2, 0.15, 0.05, 0.8, 0.9, 0.85, 0.75])

        m = compute_roc_pr_metrics(y_true, y_scores)
        assert m["roc_auc"] >= 0.95
        assert m["pr_auc"] >= 0.95
        assert m["fpr_at_95_tpr"] <= 0.1
