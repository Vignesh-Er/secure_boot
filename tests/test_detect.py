"""Unit tests for Detection Engine (Isolation Forest, Markov, EWMA, Attribution, Baseline)."""


import numpy as np
import pytest

from bootsentry.detect.attribution import AttributionEngine
from bootsentry.detect.baseline import BaselineLocalOutlierFactor, BaselineOneClassSVM
from bootsentry.detect.ewma import EWMADriftMonitor
from bootsentry.detect.isolation_forest import IsolationForestDetector
from bootsentry.detect.markov import MarkovSequenceDetector
from bootsentry.telemetry.record import BootRecord, StageTelemetry


@pytest.fixture
def normal_training_records():
    records = []
    for i in range(50):
        rec = BootRecord(
            boot_id=f"train-normal-{i}",
            timestamp_iso="2026-08-17T08:00:00Z",
            total_boot_time_ms=50.0 + (i % 5),
            stages={
                "S0": StageTelemetry("S0", t_verify_ms=5.0, t_exec_ms=2.0, t_total_ms=7.0, rss_mb=10.0),
                "S1": StageTelemetry("S1", t_verify_ms=10.0, t_exec_ms=5.0, t_total_ms=15.0, rss_mb=12.0),
                "S2": StageTelemetry("S2", t_verify_ms=15.0, t_exec_ms=10.0, t_total_ms=25.0, rss_mb=14.0),
                "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=15.0, t_total_ms=15.0, rss_mb=15.0),
            },
            event_sequence=["S0", "S1", "S2", "svc_a", "svc_b", "svc_c", "svc_attest", "svc_e"],
        )
        records.append(rec)
    return records


class TestIsolationForestDetector:
    def test_fit_and_score(self, normal_training_records, tmp_path):
        detector = IsolationForestDetector(n_estimators=50, random_state=42)
        detector.fit(normal_training_records)

        # Score normal test record
        normal_test = BootRecord(
            boot_id="test-normal",
            timestamp_iso="2026-08-17T08:00:00Z",
            total_boot_time_ms=51.0,
            stages=normal_training_records[0].stages,
        )
        score_normal = detector.score_record(normal_test)
        assert score_normal < 0.6

        # Score anomalous record with 10x resource spike
        anom_test = BootRecord(
            boot_id="test-anom",
            timestamp_iso="2026-08-17T08:00:00Z",
            total_boot_time_ms=500.0,
            stages={
                "S0": StageTelemetry("S0", t_verify_ms=50.0, t_exec_ms=20.0, t_total_ms=70.0, rss_mb=100.0),
                "S1": StageTelemetry("S1", t_verify_ms=100.0, t_exec_ms=50.0, t_total_ms=150.0, rss_mb=120.0),
                "S2": StageTelemetry("S2", t_verify_ms=150.0, t_exec_ms=100.0, t_total_ms=250.0, rss_mb=140.0),
                "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=150.0, t_total_ms=150.0, rss_mb=150.0),
            },
        )
        score_anom = detector.score_record(anom_test)
        assert score_anom > score_normal

        # Save and load model
        model_file = tmp_path / "if_model.joblib"
        detector.save(model_file)
        loaded = IsolationForestDetector.load(model_file)
        assert loaded.score_record(normal_test) == pytest.approx(score_normal, rel=1e-3)


class TestMarkovSequenceDetector:
    def test_sequence_anomaly_detection(self, normal_training_records, tmp_path):
        detector = MarkovSequenceDetector()
        detector.fit(normal_training_records)

        # Normal sequence test
        normal_rec = BootRecord(
            boot_id="test-seq-norm",
            timestamp_iso="2026-08-17T08:00:00Z",
            event_sequence=["S0", "S1", "S2", "svc_a", "svc_b", "svc_c", "svc_attest", "svc_e"],
        )
        norm_score = detector.score_record(normal_rec)
        assert norm_score < 0.5

        # Reordered / unexpected sequence test (Attack A3 style)
        reordered_rec = BootRecord(
            boot_id="test-seq-anom",
            timestamp_iso="2026-08-17T08:00:00Z",
            event_sequence=["S0", "S2", "svc_e", "svc_a", "svc_diag"],
        )
        anom_score = detector.score_record(reordered_rec)
        assert anom_score > norm_score
        assert anom_score >= 0.5

        # Save and load
        m_file = tmp_path / "markov.joblib"
        detector.save(m_file)
        loaded = MarkovSequenceDetector.load(m_file)
        assert loaded.score_record(reordered_rec) == pytest.approx(anom_score, rel=1e-3)


class TestEWMADriftMonitor:
    def test_drift_detection_over_sequence(self, normal_training_records, tmp_path):
        monitor = EWMADriftMonitor(alpha=0.3, cusum_h=3.0)
        monitor.fit(normal_training_records)

        # Send 10 normal boots
        for i in range(10):
            rec = BootRecord(
                boot_id=f"seq-norm-{i}",
                timestamp_iso="2026-08-17T08:00:00Z",
                total_boot_time_ms=50.0 + np.random.normal(0, 1.0),
            )
            is_drift, score, _ = monitor.update(rec, current_if_score=0.1)
            assert not is_drift
            assert score < 0.5

        # Send 15 progressively slower boots (Attack A4 slow-drip)
        drift_detected = False
        for i in range(15):
            rec = BootRecord(
                boot_id=f"seq-drift-{i}",
                timestamp_iso="2026-08-17T08:00:00Z",
                total_boot_time_ms=50.0 + (i * 15.0),  # Gradual accumulation
            )
            is_drift, score, _ = monitor.update(rec, current_if_score=0.1 + i * 0.05)
            if is_drift:
                drift_detected = True

        assert drift_detected is True


class TestAttributionEngine:
    def test_attribution_explanation(self, normal_training_records, tmp_path):
        engine = AttributionEngine()
        engine.fit(normal_training_records)

        # Create record with anomalous S2 execution time
        anom_rec = BootRecord(
            boot_id="test-attr-rec",
            timestamp_iso="2026-08-17T08:00:00Z",
            total_boot_time_ms=120.0,
            stages={
                "S0": StageTelemetry("S0", t_verify_ms=5.0, t_exec_ms=2.0, t_total_ms=7.0, rss_mb=10.0),
                "S1": StageTelemetry("S1", t_verify_ms=10.0, t_exec_ms=5.0, t_total_ms=15.0, rss_mb=12.0),
                "S2": StageTelemetry("S2", t_verify_ms=15.0, t_exec_ms=80.0, t_total_ms=95.0, rss_mb=14.0),
                "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=15.0, t_total_ms=15.0, rss_mb=15.0),
            },
        )

        top_attrs = engine.explain(anom_rec, top_k=3)
        assert len(top_attrs) == 3
        top_names = [a.feature_name for a in top_attrs]
        assert "t_exec_s2" in top_names or "t_total_boot" in top_names
        assert "+" in top_attrs[0].formatted_sigma
        assert "sigma" in top_attrs[0].formatted_sigma

    def test_numerical_stability_and_zero_mad_cases(self, normal_training_records, tmp_path):
        """Regression test verifying robust-z calculation under edge cases and zero-MAD features."""
        engine = AttributionEngine()
        engine.fit(normal_training_records)

        # 1. Normal record
        normal_attrs = engine.explain(normal_training_records[0], top_k=28)
        for a in normal_attrs:
            assert np.isfinite(a.robust_z)
            assert np.isfinite(a.observed_value)
            assert np.isfinite(a.baseline_median)
            assert np.isfinite(a.baseline_mad)
            assert not np.isnan(a.robust_z)

        # 2. Extreme anomalous record with zero-MAD features, large values, and negative values
        extreme_rec = BootRecord(
            boot_id="test-extreme",
            timestamp_iso="2026-08-17T08:00:00Z",
            total_boot_time_ms=100000.0,
            stages={
                "S0": StageTelemetry("S0", t_verify_ms=0.0, t_exec_ms=-1.0, rss_mb=500.0, io_bytes_read=1024 * 1024),
                "S1": StageTelemetry("S1", t_verify_ms=500.0, t_exec_ms=500.0, rss_mb=1000.0, io_bytes_written=0),
                "S2": StageTelemetry("S2", t_verify_ms=1000.0, t_exec_ms=5000.0, rss_mb=2000.0, ctx_switches_vol=10000),
                "S3": StageTelemetry("S3", t_verify_ms=0.0, t_exec_ms=10000.0, rss_mb=4000.0, page_faults_major=50),
            },
        )

        extreme_attrs = engine.explain(extreme_rec, top_k=28)
        for a in extreme_attrs:
            assert np.isfinite(a.robust_z)
            assert not np.isnan(a.robust_z)
            assert not np.isinf(a.robust_z)

        # 3. Serialization and deserialization roundtrip
        save_file = tmp_path / "attr_engine.joblib"
        engine.save(save_file)
        loaded = AttributionEngine.load(save_file)
        loaded_attrs = loaded.explain(extreme_rec, top_k=5)
        assert len(loaded_attrs) == 5
        assert loaded_attrs[0].robust_z == pytest.approx(extreme_attrs[0].robust_z, rel=1e-3)



class TestBaselines:
    def test_ocsvm_and_lof(self, normal_training_records):
        ocsvm = BaselineOneClassSVM(nu=0.1)
        ocsvm.fit(normal_training_records)
        s_svm = ocsvm.score_record(normal_training_records[0])
        assert 0.0 <= s_svm <= 1.0

        lof = BaselineLocalOutlierFactor(n_neighbors=10)
        lof.fit(normal_training_records)
        s_lof = lof.score_record(normal_training_records[0])
        assert 0.0 <= s_lof <= 1.0
