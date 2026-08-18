"""Unit tests for Stage 3 real computational services (services.py)."""

from bootsentry.boot.services import (
    DEFAULT_SERVICE_SEQUENCE,
    SERVICE_REGISTRY,
    run_svc_a,
    run_svc_attest,
    run_svc_b,
    run_svc_c,
    run_svc_diag,
    run_svc_e,
)


class TestServices:
    def test_service_registry_completeness(self):
        expected = ["svc_a", "svc_b", "svc_c", "svc_attest", "svc_e", "svc_diag"]
        for name in expected:
            assert name in SERVICE_REGISTRY
            assert callable(SERVICE_REGISTRY[name])

        for default_svc in DEFAULT_SERVICE_SEQUENCE:
            assert default_svc in SERVICE_REGISTRY

    def test_run_svc_a_networking(self):
        res = run_svc_a()
        assert res.name == "svc_a"
        assert res.status == "OK"
        assert len(res.digest) == 64
        assert res.details["interfaces_configured"] == 200

    def test_run_svc_b_crypto_kdf(self):
        res = run_svc_b()
        assert res.name == "svc_b"
        assert res.status == "OK"
        assert len(res.digest) == 64
        assert res.details["kdf_iterations"] == 1500

    def test_run_svc_c_vfs_inodes(self):
        res = run_svc_c()
        assert res.name == "svc_c"
        assert res.status == "OK"
        assert len(res.digest) == 64
        assert res.details["inodes_verified"] == 150

    def test_run_svc_attest_daemon(self):
        res = run_svc_attest()
        assert res.name == "svc_attest"
        assert res.status == "OK"
        assert len(res.digest) == 64
        assert res.details["attestation_ready"] is True

    def test_run_svc_e_matrix_math(self):
        res = run_svc_e()
        assert res.name == "svc_e"
        assert res.status == "OK"
        assert len(res.digest) == 64
        assert res.details["matrix_dim"] == 40

    def test_run_svc_diag_memory_sweep(self):
        res = run_svc_diag()
        assert res.name == "svc_diag"
        assert res.status == "OK"
        assert len(res.digest) == 64
        assert res.details["diag_blocks_checked"] == 500

    def test_service_determinism(self):
        res1 = run_svc_a()
        res2 = run_svc_a()
        assert res1.digest == res2.digest

        res3 = run_svc_e()
        res4 = run_svc_e()
        assert res3.digest == res4.digest
