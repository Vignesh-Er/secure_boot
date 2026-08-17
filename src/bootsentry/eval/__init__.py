"""Evaluation subsystem exports."""

from bootsentry.eval.collector import collect_single_real_boot, run_data_collection
from bootsentry.eval.evaluate import compute_roc_pr_metrics, run_comprehensive_evaluation
from bootsentry.eval.trainer import train_all_models

__all__ = [
    "collect_single_real_boot",
    "compute_roc_pr_metrics",
    "run_comprehensive_evaluation",
    "run_data_collection",
    "train_all_models",
]
