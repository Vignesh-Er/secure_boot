"""Real system service workloads executed by Stage 3 (Init).

Note: In accordance with Security Invariant 5, all services perform genuine
computation (hashing, matrix operations, config synthesis) with NO time.sleep().
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from typing import Dict, List, Tuple


@dataclass
class ServiceExecutionResult:
    name: str
    digest: str
    status: str
    details: Dict[str, object]


def run_svc_a() -> ServiceExecutionResult:
    """Service A: Network/Hardware stack initialization.

    Performs cryptographic MAC table construction and interface synthesis.
    """
    hasher = hashlib.sha256()
    # Compute ARP/MAC routing simulation with 200 synthetic interfaces
    entries = []
    for i in range(200):
        raw = f"eth{i}:mac=52:54:00:12:34:{i:02x}:ip=192.168.1.{i+1}".encode()
        h = hashlib.sha256(raw).hexdigest()
        hasher.update(h.encode())
        entries.append(h[:8])

    digest = hasher.hexdigest()
    return ServiceExecutionResult(
        name="svc_a",
        digest=digest,
        status="OK",
        details={"interfaces_configured": len(entries), "mac_table_hash": digest[:16]},
    )


def run_svc_b() -> ServiceExecutionResult:
    """Service B: Cryptographic subsystem initialization.

    Generates entropy pools and computes PBKDF2-style key derivation loops.
    """
    salt = b"bootsentry_secure_boot_entropy_seed"
    key = hashlib.pbkdf2_hmac("sha256", b"system_master_kdf_seed", salt, iterations=1500)
    digest = hashlib.sha256(key).hexdigest()

    return ServiceExecutionResult(
        name="svc_b",
        digest=digest,
        status="OK",
        details={"kdf_iterations": 1500, "entropy_pool_digest": digest[:16]},
    )


def run_svc_c() -> ServiceExecutionResult:
    """Service C: Storage engine and VFS table verification.

    Performs filesystem inode tree simulation and metadata integrity hashing.
    """
    inodes = {}
    hasher = hashlib.sha256()
    for inode_id in range(150):
        entry = {
            "inode": inode_id,
            "path": f"/sys/devices/virtual/block/vol_{inode_id}",
            "blocks": [inode_id * 4 + k for k in range(8)],
            "mode": 0o644,
        }
        b = json.dumps(entry, sort_keys=True).encode()
        ihash = hashlib.sha256(b).hexdigest()
        hasher.update(ihash.encode())
        inodes[inode_id] = ihash[:8]

    digest = hasher.hexdigest()
    return ServiceExecutionResult(
        name="svc_c",
        digest=digest,
        status="OK",
        details={"inodes_verified": len(inodes), "vfs_tree_hash": digest[:16]},
    )


def run_svc_attest() -> ServiceExecutionResult:
    """Service Attest: Platform attestation daemon preparation.

    Computes cryptographic integrity digest for attestation quotes.
    """
    payload = b"AttestationEngineReady:" + hashlib.sha256(b"quote_engine_v1").digest()
    digest = hashlib.sha256(payload).hexdigest()
    return ServiceExecutionResult(
        name="svc_attest",
        digest=digest,
        status="OK",
        details={"attestation_ready": True, "engine_digest": digest[:16]},
    )


def run_svc_e() -> ServiceExecutionResult:
    """Service E: System health and matrix consistency verification.

    Executes matrix multiplications and numerical consistency tests.
    """
    # 40x40 matrix multiplication
    size = 40
    mat_a = [[math.sin(i * size + j) for j in range(size)] for i in range(size)]
    mat_b = [[math.cos(j * size + i) for j in range(size)] for i in range(size)]
    mat_c = [[0.0 for _ in range(size)] for _ in range(size)]

    for i in range(size):
        for k in range(size):
            for j in range(size):
                mat_c[i][j] += mat_a[i][k] * mat_b[k][j]

    raw = "".join(f"{mat_c[i][j]:.4f}" for i in range(size) for j in range(0, size, 5)).encode()
    digest = hashlib.sha256(raw).hexdigest()

    return ServiceExecutionResult(
        name="svc_e",
        digest=digest,
        status="OK",
        details={"matrix_dim": size, "consistency_digest": digest[:16]},
    )


def run_svc_diag() -> ServiceExecutionResult:
    """Optional Diagnostic Service (used in attack scenario A3).

    Performs deep memory diagnostics and extended memory hashing.
    """
    # 1000 iteration memory pattern sweep
    hasher = hashlib.sha256()
    for block in range(500):
        pattern = bytes([(block * 37 + x) % 256 for x in range(64)])
        hasher.update(pattern)

    digest = hasher.hexdigest()
    return ServiceExecutionResult(
        name="svc_diag",
        digest=digest,
        status="OK",
        details={"diag_blocks_checked": 500, "memory_sweep_hash": digest[:16]},
    )


SERVICE_REGISTRY = {
    "svc_a": run_svc_a,
    "svc_b": run_svc_b,
    "svc_c": run_svc_c,
    "svc_attest": run_svc_attest,
    "svc_e": run_svc_e,
    "svc_diag": run_svc_diag,
}

DEFAULT_SERVICE_SEQUENCE: List[str] = ["svc_a", "svc_b", "svc_c", "svc_attest", "svc_e"]
