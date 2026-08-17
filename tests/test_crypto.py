"""Unit and negative tests for BootSentry PQC Cryptographic Layer."""

import hashlib
import json
import pytest
from pathlib import Path

from bootsentry.crypto.keys import (
    generate_stage_keypair,
    save_keypair,
    load_public_key,
    load_secret_key,
    generate_all_system_keys,
)
from bootsentry.crypto.manifest import Manifest, compute_payload_sha256
from bootsentry.crypto.provider import (
    get_provider,
    list_supported_algorithms,
    AlgorithmNotFoundError,
    MalformedKeyError,
    CryptoError,
)
from bootsentry.crypto.sign import sign_manifest, sign_stage_manifest_file
from bootsentry.crypto.verify import verify_manifest, CryptoVerifyResult
from bootsentry.crypto.benchmark import benchmark_algorithm, run_all_benchmarks


class TestPQCProvider:
    def test_list_supported_algorithms(self):
        algs = list_supported_algorithms()
        assert "ML-DSA-65" in algs
        assert "ML-DSA-44" in algs
        assert "ML-DSA-87" in algs

    def test_unsupported_algorithm_raises(self):
        with pytest.raises(AlgorithmNotFoundError):
            get_provider("NON_EXISTENT_PQC_ALG")

    @pytest.mark.parametrize("alg", ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"])
    def test_keygen_sign_verify_happy_path(self, alg):
        provider = get_provider(alg)
        pk, sk = provider.keygen()
        assert len(pk) == provider.public_key_size
        assert len(sk) == provider.secret_key_size

        msg = b"Secure boot stage S1 binary measurement hash payload"
        sig = provider.sign(sk, msg)
        assert len(sig) == provider.signature_size

        assert provider.verify(pk, msg, sig) is True

    def test_verify_with_wrong_public_key(self):
        provider = get_provider("ML-DSA-65")
        pk1, sk1 = provider.keygen()
        pk2, sk2 = provider.keygen()

        msg = b"Authentic payload"
        sig1 = provider.sign(sk1, msg)

        # Verification with wrong public key must fail
        assert provider.verify(pk2, msg, sig1) is False

    def test_verify_with_tampered_message(self):
        provider = get_provider("ML-DSA-65")
        pk, sk = provider.keygen()

        msg = b"Authentic payload"
        sig = provider.sign(sk, msg)

        tampered_msg = b"Attacker modified payload"
        assert provider.verify(pk, tampered_msg, sig) is False

    def test_verify_with_truncated_signature(self):
        provider = get_provider("ML-DSA-65")
        pk, sk = provider.keygen()
        msg = b"Authentic payload"
        sig = provider.sign(sk, msg)

        truncated_sig = sig[: len(sig) // 2]
        assert provider.verify(pk, msg, truncated_sig) is False

    def test_sign_with_invalid_secret_key_length(self):
        provider = get_provider("ML-DSA-65")
        with pytest.raises(MalformedKeyError):
            provider.sign(b"short_key", b"test")


class TestManifestAndVerification:
    @pytest.fixture
    def s1_keys(self):
        return generate_stage_keypair("S1", "ML-DSA-65")

    @pytest.fixture
    def s2_keys(self):
        return generate_stage_keypair("S2", "ML-DSA-65")

    @pytest.fixture
    def valid_manifest(self, s1_keys):
        payload = b"print('Hello Kernel Stage S1')"
        digest, size = compute_payload_sha256(payload)
        m = Manifest(
            stage_id="S1",
            version="1.4.0",
            security_version_counter=5,
            algorithm="ML-DSA-65",
            payload_sha256=digest,
            payload_size=size,
            expected_pcr="a" * 64,
            metadata={"description": "Stage 1 Bootloader"},
        )
        return sign_manifest(m, s1_keys.secret_key_bytes), payload

    def test_manifest_canonicalization_determinism(self):
        m1 = Manifest(
            stage_id="S1",
            version="1.0.0",
            security_version_counter=1,
            algorithm="ML-DSA-65",
            payload_sha256="abcd" * 16,
            payload_size=100,
            expected_pcr="1234" * 16,
            metadata={"b": 2, "a": 1},
        )
        m2 = Manifest(
            stage_id="S1",
            version="1.0.0",
            security_version_counter=1,
            algorithm="ML-DSA-65",
            payload_sha256="abcd" * 16,
            payload_size=100,
            expected_pcr="1234" * 16,
            metadata={"a": 1, "b": 2},
        )
        assert m1.canonical_bytes() == m2.canonical_bytes()
        assert m1.canonical_digest() == m2.canonical_digest()

    def test_verify_manifest_happy_path(self, valid_manifest, s1_keys):
        m, payload = valid_manifest
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s1_keys.public_key_bytes,
            payload_bytes=payload,
            expected_stage_id="S1",
        )
        assert res.success is True
        assert "verified successfully" in res.reason
        assert res.stage_id == "S1"
        assert res.latency_ms >= 0.0

    def test_negative_wrong_stage_binding(self, valid_manifest, s1_keys):
        m, payload = valid_manifest
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s1_keys.public_key_bytes,
            payload_bytes=payload,
            expected_stage_id="S2",  # Mismatched expected stage
        )
        assert res.success is False
        assert "Stage ID mismatch" in res.reason

    def test_negative_unsigned_manifest(self, valid_manifest, s1_keys):
        m, payload = valid_manifest
        m.signature = None
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s1_keys.public_key_bytes,
            payload_bytes=payload,
        )
        assert res.success is False
        assert "unsigned" in res.reason

    def test_negative_corrupted_signature_hex(self, valid_manifest, s1_keys):
        m, payload = valid_manifest
        m.signature = "NOT_HEX_DATA!!"
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s1_keys.public_key_bytes,
            payload_bytes=payload,
        )
        assert res.success is False
        assert "invalid hexadecimal" in res.reason

    def test_negative_tampered_payload_content(self, valid_manifest, s1_keys):
        m, payload = valid_manifest
        tampered_payload = payload + b"MALICIOUS_BACKDOOR_INJECTION"
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s1_keys.public_key_bytes,
            payload_bytes=tampered_payload,
        )
        assert res.success is False
        assert "Payload SHA-256 digest mismatch" in res.reason

    def test_negative_tampered_payload_size(self, valid_manifest, s1_keys):
        m, _ = valid_manifest
        # Payload with correct sha but fake size (impossible in reality, but test boundary)
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s1_keys.public_key_bytes,
            payload_bytes=b"different",
        )
        assert res.success is False

    def test_negative_tampered_manifest_metadata(self, valid_manifest, s1_keys):
        m, payload = valid_manifest
        # Attacker modifies security_version_counter after signing
        m.security_version_counter = 999
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s1_keys.public_key_bytes,
            payload_bytes=payload,
        )
        assert res.success is False
        assert "invalid signature" in res.reason

    def test_negative_cross_stage_replay(self, valid_manifest, s2_keys):
        m, payload = valid_manifest
        # Stage 1 manifest verified against Stage 2 public key
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s2_keys.public_key_bytes,
            payload_bytes=payload,
        )
        assert res.success is False

    def test_negative_wrong_algorithm_fail_closed(self, valid_manifest, s1_keys):
        m, payload = valid_manifest
        m.algorithm = "RSA-512-VULNERABLE"
        res = verify_manifest(
            manifest=m,
            public_key_bytes=s1_keys.public_key_bytes,
            payload_bytes=payload,
        )
        assert res.success is False
        assert "failed closed" in res.reason or "not supported" in res.reason


class TestKeyStorageAndBenchmarks:
    def test_key_save_and_load(self, tmp_path):
        kp = generate_stage_keypair("S2", "ML-DSA-65")
        priv_p, pub_p = save_keypair(kp, tmp_path)

        st_pub, alg_pub, pk_b = load_public_key(pub_p)
        assert st_pub == "S2"
        assert alg_pub == "ML-DSA-65"
        assert pk_b == kp.public_key_bytes

        st_priv, alg_priv, sk_b = load_secret_key(priv_p)
        assert st_priv == "S2"
        assert alg_priv == "ML-DSA-65"
        assert sk_b == kp.secret_key_bytes

    def test_generate_all_system_keys(self, tmp_path):
        kps = generate_all_system_keys(tmp_path, "ML-DSA-65")
        assert len(kps) == 5
        assert set(kps.keys()) == {"S0", "S1", "S2", "S3", "ATTEST"}

    def test_benchmark_execution(self):
        res = benchmark_algorithm("ML-DSA-65", iterations=2)
        assert res.algorithm == "ML-DSA-65"
        assert res.public_key_bytes == 1952
        assert res.signature_bytes == 3293
        assert res.sign_ms_mean > 0.0
        assert res.verify_ms_mean > 0.0

    def test_run_all_benchmarks(self):
        results = run_all_benchmarks(iterations=1)
        assert len(results) >= 3
        algorithms = [r.algorithm for r in results]
        assert "ML-DSA-65" in algorithms
        assert "ML-DSA-44" in algorithms
        assert "ML-DSA-87" in algorithms


class TestManifestFileOperationsAndCLI:
    def test_manifest_save_and_load(self, tmp_path):
        payload_file = tmp_path / "payload.bin"
        payload_file.write_bytes(b"Kernel binary code simulation")
        digest, size = compute_payload_sha256(payload_file)

        m = Manifest(
            stage_id="S2",
            version="2.0.1",
            security_version_counter=3,
            algorithm="ML-DSA-65",
            payload_sha256=digest,
            payload_size=size,
            expected_pcr="beef" * 16,
            metadata={"kernel_version": "6.1.0"},
        )
        m_file = tmp_path / "s2_manifest.json"
        m.save(m_file)

        loaded_m = Manifest.load(m_file)
        assert loaded_m.stage_id == "S2"
        assert loaded_m.version == "2.0.1"
        assert loaded_m.security_version_counter == 3
        assert loaded_m.payload_sha256 == digest

    def test_sign_stage_manifest_file(self, tmp_path):
        # Setup key
        kp = generate_stage_keypair("S3", "ML-DSA-65")
        priv_file, pub_file = save_keypair(kp, tmp_path / "keys")

        # Setup manifest
        m = Manifest(
            stage_id="S3",
            version="1.0.0",
            security_version_counter=1,
            algorithm="ML-DSA-65",
            payload_sha256="1234" * 16,
            payload_size=64,
            expected_pcr="0000" * 16,
        )
        m_file = tmp_path / "s3_manifest.json"
        m.save(m_file)

        # Sign file
        signed_m = sign_stage_manifest_file(m_file, priv_file)
        assert signed_m.signature is not None

        # Verify
        _, _, pk_bytes = load_public_key(pub_file)
        res = verify_manifest(signed_m, pk_bytes)
        assert res.success is True

    def test_manifest_load_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            Manifest.load(tmp_path / "non_existent.json")

    def test_compute_payload_sha256_not_found(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            compute_payload_sha256(tmp_path / "missing_file.bin")

    def test_load_keys_not_found(self, tmp_path):
        with pytest.raises(CryptoError):
            load_public_key(tmp_path / "missing_pub.json")
        with pytest.raises(CryptoError):
            load_secret_key(tmp_path / "missing_priv.json")

    def test_load_keys_malformed_json(self, tmp_path):
        bad_pub = tmp_path / "bad_pub.json"
        bad_pub.write_text('{"stage_id": "S1"}', encoding="utf-8")
        with pytest.raises(MalformedKeyError):
            load_public_key(bad_pub)

        bad_priv = tmp_path / "bad_priv.json"
        bad_priv.write_text('{"stage_id": "S1"}', encoding="utf-8")
        with pytest.raises(MalformedKeyError):
            load_secret_key(bad_priv)

