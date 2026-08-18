"""Detector 1: Isolation Forest Behavioral Anomaly Model."""

from __future__ import annotations

from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from bootsentry.features.extractor import (
    FEATURE_NAMES,
    extract_feature_matrix,
    extract_feature_vector,
)
from bootsentry.telemetry.record import FEATURE_VERSION, BootRecord


class IsolationForestDetector:
    """Isolation Forest anomaly detector with StandardScaler preprocessing."""

    def __init__(
        self,
        n_estimators: int = 200,
        contamination: str | float = "auto",
        random_state: int = 42,
    ):
        self.n_estimators = n_estimators
        self.contamination = contamination
        self.random_state = random_state
        self.feature_version = FEATURE_VERSION

        self.scaler: StandardScaler | None = None
        self.model: IsolationForest | None = None
        self.score_threshold: float = 0.5  # Normalized anomaly threshold [0, 1]

    def fit(self, records: list[BootRecord]) -> IsolationForestDetector:
        """Fit scaler and Isolation Forest strictly on clean normal records."""
        X = extract_feature_matrix(records)
        if X.shape[0] < 5:
            raise ValueError(f"Insufficient training samples ({X.shape[0]}), minimum 5 required.")

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)

        # Calibrate baseline scores on training set
        raw_scores = -self.model.score_samples(X_scaled)  # higher = more anomalous
        self.score_threshold = float(np.percentile(raw_scores, 95))  # 95th percentile baseline
        return self

    def score_record(self, record: BootRecord) -> float:
        """Calculate normalized anomaly score in [0, 1] for a single BootRecord."""
        if not self.model or not self.scaler:
            raise RuntimeError("Model is not trained. Call fit() or load() first.")

        if record.feature_version != self.feature_version:
            raise ValueError(
                f"Feature version mismatch: model expects v{self.feature_version}, record has v{record.feature_version}"
            )

        vec = extract_feature_vector(record).reshape(1, -1)
        vec_scaled = self.scaler.transform(vec)

        # raw score: lower means more anomalous in sklearn, so invert
        raw_score = -float(self.model.score_samples(vec_scaled)[0])

        # Normalize score into roughly [0, 1] with sigmoid/threshold mapping
        # raw_score typically ranges from ~0.35 (very normal) to ~0.75 (highly anomalous)
        # Using centered logistic mapping:
        norm_score = 1.0 / (1.0 + np.exp(-12.0 * (raw_score - self.score_threshold)))
        return float(np.clip(norm_score, 0.0, 1.0))

    def predict(self, record: BootRecord) -> tuple[bool, float]:
        """Return (is_anomalous, anomaly_score)."""
        score = self.score_record(record)
        return score >= 0.5, score

    def save(self, file_path: Path | str) -> None:
        """Save model bundle to joblib file."""
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "feature_version": self.feature_version,
            "scaler": self.scaler,
            "model": self.model,
            "score_threshold": self.score_threshold,
            "n_estimators": self.n_estimators,
            "contamination": self.contamination,
            "random_state": self.random_state,
            "feature_names": FEATURE_NAMES,
        }
        joblib.dump(bundle, path)

    @classmethod
    def load(cls, file_path: Path | str) -> IsolationForestDetector:
        """Load model bundle from joblib file."""
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Model file not found: {path}")

        bundle = joblib.load(path)
        if bundle.get("feature_version") != FEATURE_VERSION:
            raise ValueError(
                f"Model feature version {bundle.get('feature_version')} is incompatible with current {FEATURE_VERSION}"
            )

        detector = cls(
            n_estimators=bundle["n_estimators"],
            contamination=bundle["contamination"],
            random_state=bundle["random_state"],
        )
        detector.scaler = bundle["scaler"]
        detector.model = bundle["model"]
        detector.score_threshold = bundle["score_threshold"]
        return detector

    def export_c_code(self, output_path: Path | str, max_trees: int = 8) -> Path:
        """Export trained decision trees to freestanding C99 source file."""
        if not self.model or not self.scaler:
            raise RuntimeError("Model is not trained. Cannot export C code.")

        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        means = self.scaler.mean_
        scales = self.scaler.scale_
        num_trees = min(max_trees, len(self.model.estimators_))

        lines = [
            '#include "bootsentry_telemetry.h"',
            "#include <math.h>",
            "",
            f"/* Transpiled Isolation Forest Anomaly Evaluator ({num_trees} Real Decision Trees) */",
            f"static const float SCALER_MEANS[{len(means)}] = {{",
            "    " + ", ".join(f"{m:.6f}f" for m in means),
            "};",
            f"static const float SCALER_SCALES[{len(scales)}] = {{",
            "    " + ", ".join(f"{s:.6f}f" for s in scales),
            "};",
            f"static const float SCORE_THRESHOLD = {self.score_threshold:.6f}f;",
            f"static const int NUM_EXPORTED_TREES = {num_trees};",
            "",
        ]

        # Generate individual tree path length evaluators
        for tree_idx in range(num_trees):
            tree = self.model.estimators_[tree_idx].tree_
            lines.append(
                f"static float evaluate_tree_{tree_idx}(const float x[BOOTSENTRY_NUM_FEATURES]) {{"
            )

            def emit_node(node_id: int, depth: int, cur_tree=tree) -> list[str]:
                indent = "    " * (depth + 1)
                left = cur_tree.children_left[node_id]
                right = cur_tree.children_right[node_id]
                if left == right:  # Leaf node
                    return [f"{indent}return (float){depth};"]
                feat = cur_tree.feature[node_id]
                thresh = cur_tree.threshold[node_id]
                node_lines = [f"{indent}if (x[{feat}] <= {thresh:.6f}f) {{"]
                node_lines.extend(emit_node(left, depth + 1, cur_tree))
                node_lines.append(f"{indent}}} else {{")
                node_lines.extend(emit_node(right, depth + 1, cur_tree))
                node_lines.append(f"{indent}}}")
                return node_lines

            lines.extend(emit_node(0, 0, tree))
            lines.append("}\n")


        lines.extend(
            [
                "float bootsentry_evaluate_isolation_forest(const float features[BOOTSENTRY_NUM_FEATURES]) {",
                "    float x_scaled[BOOTSENTRY_NUM_FEATURES];",
                "    for (int i = 0; i < BOOTSENTRY_NUM_FEATURES; i++) {",
                "        x_scaled[i] = (features[i] - SCALER_MEANS[i]) / (SCALER_SCALES[i] > 1e-6f ? SCALER_SCALES[i] : 1.0f);",
                "    }",
                "",
                "    float total_path_length = 0.0f;",
            ]
        )

        for t in range(num_trees):
            lines.append(f"    total_path_length += evaluate_tree_{t}(x_scaled);")

        lines.extend(
            [
                "    float avg_path_length = total_path_length / (float)NUM_EXPORTED_TREES;",
                "    /* Standard Isolation Forest average path length normalizer c(256) */",
                "    float c_n = 2.0f * (logf(255.0f) + 0.5772156649f) - (2.0f * 255.0f / 256.0f);",
                "    float raw_score = powf(2.0f, -avg_path_length / c_n);",
                "",
                "    /* Logistic mapping matching Python model */",
                "    float norm_score = 1.0f / (1.0f + expf(-12.0f * (raw_score - SCORE_THRESHOLD)));",
                "    if (norm_score < 0.0f) norm_score = 0.0f;",
                "    if (norm_score > 1.0f) norm_score = 1.0f;",
                "    return norm_score;",
                "}",
                "",
            ]
        )

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")

        return path


