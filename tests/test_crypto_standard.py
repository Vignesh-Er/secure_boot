"""Regression and standards compliance tests for NIST FIPS 204 ML-DSA migration.

Ensures committed keys, manifests, and providers adhere strictly to FIPS 204
specifications and rejects round-3 CRYSTALS-Dilithium artifacts (F-01 guard).
"""

from __future__ import annotations

import json
from pathlib import Path
import unicodedata
import pytest

from dilithium_py.dilithium import Dilithium3
from dilithium_py.ml_dsa import ML_DSA_65

from bootsentry.crypto.keys import load_public_key, load_secret_key
from bootsentry.crypto.manifest import Manifest
from bootsentry.crypto.provider import (
    AlgorithmNotFoundError,
    get_provider,
    list_supported_algorithms,
)
from bootsentry.crypto.verify import verify_manifest


class TestFIPS204Compliance:
    def test_committed_keys_sizes(self):
        """Every committed stage key in config/keys must match FIPS 204 ML-DSA-65 sizes."""
        keys_dir = Path("config/keys")
        assert keys_dir.exists(), "config/keys directory must exist"

        stages = ["s0", "s1", "s2", "s3", "attest"]
        for stage in stages:
            pub_path = keys_dir / f"{stage}_public.json"
            priv_path = keys_dir / f"{stage}_private.json"

            _, alg_pub, pk_bytes = load_public_key(pub_path)
            _, alg_priv, sk_bytes = load_secret_key(priv_path)

            assert alg_pub == "ML-DSA-65"
            assert alg_priv == "ML-DSA-65"
            assert len(pk_bytes) == 1952, f"Public key for {stage} must be 1952 bytes (FIPS 204)"
            assert len(sk_bytes) == 4032, f"Secret key for {stage} must be 4032 bytes (FIPS 204)"

    def test_committed_manifest_fips204_verification_passes(self):
        """Committed s1 manifest must verify with dilithium_py.ml_dsa.ML_DSA_65."""
        m_path = Path("config/stages/s1_manifest.json")
        k_path = Path("config/keys/s0_public.json")
        payload_path = Path("config/stages/s1_payload.bin")

        m = Manifest.load(m_path)
        _, _, pk_bytes = load_public_key(k_path)
        payload_bytes = payload_path.read_bytes()

        # Gate 1 verification must pass
        res = verify_manifest(m, pk_bytes, payload_bytes=payload_bytes)
        assert res.success is True, f"Verification failed: {res.reason}"

        # Direct dilithium_py FIPS 204 call must pass
        canonical_data = m.canonical_bytes()
        sig_bytes = bytes.fromhex(m.signature)
        assert len(sig_bytes) == 3309, "Signature must be 3309 bytes (FIPS 204 ML-DSA-65)"
        assert ML_DSA_65.verify(pk_bytes, canonical_data, sig_bytes, ctx=b"") is True

    def test_regression_f01_dilithium3_must_fail_on_fips204_manifest(self):
        """CRITICAL REGRESSION GUARD (F-01): Round-3 Dilithium3 must return False on FIPS 204 signature."""
        m_path = Path("config/stages/s1_manifest.json")
        k_path = Path("config/keys/s0_public.json")

        m = Manifest.load(m_path)
        _, _, pk_bytes = load_public_key(k_path)
        canonical_data = m.canonical_bytes()
        sig_bytes = bytes.fromhex(m.signature)

        # Dilithium3 round-3 verify must fail on FIPS 204 encoded signature
        dilithium3_result = False
        try:
            dilithium3_result = bool(Dilithium3.verify(pk_bytes, canonical_data, sig_bytes))
        except (ValueError, TypeError, IndexError, KeyError, RuntimeError):
            dilithium3_result = False

        assert dilithium3_result is False, "FIPS 204 signature must NOT be accepted by round-3 Dilithium3"

    def test_round3_algorithm_names_raise_informative_error(self):
        """Requesting legacy round-3 names must raise AlgorithmNotFoundError with exact message."""
        for alg in ["Dilithium2", "Dilithium3", "Dilithium5"]:
            with pytest.raises(AlgorithmNotFoundError, match="Dilithium \\(round-3\\) is not supported; this build uses NIST FIPS 204 ML-DSA."):
                get_provider(alg)


class TestNegativeCryptoMatrix:
    @pytest.fixture
    def s1_context(self):
        m_path = Path("config/stages/s1_manifest.json")
        k_path = Path("config/keys/s0_public.json")
        payload_path = Path("config/stages/s1_payload.bin")
        m = Manifest.load(m_path)
        _, _, pk_bytes = load_public_key(k_path)
        payload = payload_path.read_bytes()
        return m, pk_bytes, payload

    def test_negative_bit_flipped_signature(self, s1_context):
        m, pk, payload = s1_context
        sig_bytes = bytearray(bytes.fromhex(m.signature))
        sig_bytes[10] ^= 0x01  # Flip one bit
        m.signature = sig_bytes.hex()
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_truncated_signature(self, s1_context):
        m, pk, payload = s1_context
        m.signature = m.signature[:64]
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_empty_signature(self, s1_context):
        m, pk, payload = s1_context
        m.signature = ""
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_non_hex_signature(self, s1_context):
        m, pk, payload = s1_context
        m.signature = "INVALID_HEX_STRING_!"
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_svn_tampered_post_sign(self, s1_context):
        m, pk, payload = s1_context
        m.security_version_counter += 1
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_payload_digest_tampered_post_sign(self, s1_context):
        m, pk, payload = s1_context
        m.payload_sha256 = "00" * 32
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_payload_size_tampered_post_sign(self, s1_context):
        m, pk, payload = s1_context
        m.payload_size += 100
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_version_tampered_post_sign(self, s1_context):
        m, pk, payload = s1_context
        m.version = "9.9.9"
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_expected_pcr_tampered_post_sign(self, s1_context):
        m, pk, payload = s1_context
        m.expected_pcr = "ff" * 32
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_payload_swapped(self, s1_context):
        m, pk, _ = s1_context
        tampered_payload = b"MALICIOUS_SWAPPED_PAYLOAD"
        res = verify_manifest(m, pk, tampered_payload)
        assert res.success is False

    def test_negative_wrong_public_key(self, s1_context):
        m, _, payload = s1_context
        # Use S1 key instead of S0 key
        _, _, s1_pk = load_public_key("config/keys/s1_public.json")
        res = verify_manifest(m, s1_pk, payload)
        assert res.success is False

    def test_negative_attacker_key_substitution(self, s1_context):
        m, _, payload = s1_context
        provider = get_provider("ML-DSA-65")
        attacker_pk, attacker_sk = provider.keygen()
        # Attacker resigns with own key
        m.signature = provider.sign(attacker_sk, m.canonical_bytes()).hex()
        # Verifier checks with genuine OEM root key
        _, _, root_pk = load_public_key("config/keys/s0_public.json")
        res = verify_manifest(m, root_pk, payload)
        assert res.success is False

    def test_negative_cross_stage_replay(self, s1_context):
        m, pk, payload = s1_context
        # Try to verify S1 manifest asserting it is S2
        res = verify_manifest(m, pk, payload, expected_stage_id="S2")
        assert res.success is False
        assert "Stage ID mismatch" in res.reason

    def test_negative_stage_id_relabel(self, s1_context):
        m, pk, payload = s1_context
        m.stage_id = "S2"
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_algorithm_downgrade(self, s1_context):
        m, pk, payload = s1_context
        m.algorithm = "RSA-2048"
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_unknown_algorithm(self, s1_context):
        m, pk, payload = s1_context
        m.algorithm = "UNKNOWN_CRYPTO_SCHEME"
        res = verify_manifest(m, pk, payload)
        assert res.success is False

    def test_negative_malformed_and_empty_public_key(self, s1_context):
        m, _, payload = s1_context
        assert verify_manifest(m, b"", payload).success is False
        assert verify_manifest(m, b"SHORT", payload).success is False
        assert verify_manifest(m, b"A" * 1951, payload).success is False
        assert verify_manifest(m, b"A" * 1953, payload).success is False

    def test_negative_unicode_normalization_confusion(self, s1_context):
        m, pk, payload = s1_context
        # Create manifest with NFC vs NFD unicode in metadata
        nfc_str = unicodedata.normalize("NFC", "café")
        nfd_str = unicodedata.normalize("NFD", "café")
        m.metadata = {"tag": nfc_str}
        provider = get_provider("ML-DSA-65")
        _, _, s0_sk = load_secret_key("config/keys/s0_private.json")
        m.signature = provider.sign(s0_sk, m.canonical_bytes()).hex()

        # Tamper to NFD
        m.metadata = {"tag": nfd_str}
        res = verify_manifest(m, pk, payload)
        assert res.success is False
