"""Detector 2: First-Order Markov Chain Event Sequence Anomaly Model."""

from __future__ import annotations

import collections
import json
import math
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

import joblib

from bootsentry.telemetry.record import BootRecord


class MarkovSequenceDetector:
    """Models boot stage and service execution sequences using a 1st-order Markov chain.

    Utilizes Laplace smoothing (+1 pseudocount) and calculates sequence log-likelihood.
    Detects reordered, omitted, or unexpected service launches (e.g. Attack A3).
    """

    def __init__(self, laplace_alpha: float = 1.0):
        self.laplace_alpha = laplace_alpha
        self.states: Set[str] = set()
        self.transition_counts: Dict[str, Dict[str, int]] = collections.defaultdict(
            lambda: collections.defaultdict(int)
        )
        self.start_counts: Dict[str, int] = collections.defaultdict(int)
        self.total_sequences: int = 0
        self.threshold_nll: float = 3.0  # Mean negative log likelihood threshold

    def fit(self, records: List[BootRecord]) -> MarkovSequenceDetector:
        """Fit transition matrix on normal boot event sequences."""
        self.states = set()
        self.transition_counts = collections.defaultdict(lambda: collections.defaultdict(int))
        self.start_counts = collections.defaultdict(int)
        self.total_sequences = len(records)

        all_nlls: List[float] = []

        for rec in records:
            seq = rec.event_sequence
            if not seq:
                continue

            self.states.update(seq)
            self.start_counts[seq[0]] += 1

            for i in range(len(seq) - 1):
                s_from, s_to = seq[i], seq[i + 1]
                self.transition_counts[s_from][s_to] += 1

        # Calibrate baseline NLL threshold on training set
        for rec in records:
            if rec.event_sequence:
                nll, _ = self.compute_nll(rec.event_sequence)
                all_nlls.append(nll)

        if all_nlls:
            self.threshold_nll = float(max(all_nlls)) + 0.5
        return self

    def transition_prob(self, s_from: str, s_to: str) -> float:
        """Calculate transition probability P(s_to | s_from) with Laplace smoothing."""
        num_states = max(1, len(self.states))
        from_dict = self.transition_counts.get(s_from, {})
        count_from_to = from_dict.get(s_to, 0)
        total_from = sum(from_dict.values())

        # Laplace smoothing: (count + alpha) / (total + alpha * |V|)
        prob = (count_from_to + self.laplace_alpha) / (total_from + self.laplace_alpha * num_states)
        return prob

    def compute_nll(self, sequence: List[str]) -> Tuple[float, List[Tuple[str, str, float]]]:
        """Compute Mean Negative Log-Likelihood and list of transition probabilities."""
        if len(sequence) < 2:
            return 0.0, []

        log_sum = 0.0
        transitions_detail = []

        for i in range(len(sequence) - 1):
            s_from, s_to = sequence[i], sequence[i + 1]
            p = self.transition_prob(s_from, s_to)
            log_p = math.log(p)
            log_sum += log_p
            transitions_detail.append((s_from, s_to, p))

        num_transitions = len(sequence) - 1
        mean_nll = -log_sum / num_transitions
        return mean_nll, transitions_detail

    def score_record(self, record: BootRecord) -> float:
        """Score sequence anomaly in [0, 1]. Higher indicates abnormal ordering."""
        seq = record.event_sequence
        if len(seq) < 2:
            return 0.0

        nll, transitions = self.compute_nll(seq)

        # Check for completely unseen transitions (count == 0 in training data)
        unseen_count = 0
        for s_from, s_to, _ in transitions:
            if self.transition_counts.get(s_from, {}).get(s_to, 0) == 0:
                unseen_count += 1

        # Anomaly score combining NLL and unseen transition penalties
        # Sigmoid over normalized NLL ratio + unseen boost
        nll_ratio = nll / (self.threshold_nll + 1e-6)
        score = 1.0 / (1.0 + math.exp(-4.0 * (nll_ratio - 1.0)))
        if unseen_count > 0:
            score = min(1.0, score + 0.3 * unseen_count)

        return float(min(1.0, max(0.0, score)))

    def save(self, file_path: Path | str) -> None:
        path = Path(file_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        bundle = {
            "laplace_alpha": self.laplace_alpha,
            "states": list(self.states),
            "transition_counts": {k: dict(v) for k, v in self.transition_counts.items()},
            "start_counts": dict(self.start_counts),
            "total_sequences": self.total_sequences,
            "threshold_nll": self.threshold_nll,
        }
        joblib.dump(bundle, path)

    @classmethod
    def load(cls, file_path: Path | str) -> MarkovSequenceDetector:
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Markov model not found: {path}")

        bundle = joblib.load(path)
        detector = cls(laplace_alpha=bundle["laplace_alpha"])
        detector.states = set(bundle["states"])
        detector.transition_counts = collections.defaultdict(
            lambda: collections.defaultdict(int),
            {k: collections.defaultdict(int, v) for k, v in bundle["transition_counts"].items()},
        )
        detector.start_counts = collections.defaultdict(int, bundle["start_counts"])
        detector.total_sequences = bundle["total_sequences"]
        detector.threshold_nll = bundle["threshold_nll"]
        return detector
