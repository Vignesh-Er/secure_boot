"""Attack scenarios and benign control exports."""

from bootsentry.attacks.a1_downgrade import execute_attack_a1
from bootsentry.attacks.a2_toctou import execute_attack_a2
from bootsentry.attacks.a3_reorder import execute_attack_a3
from bootsentry.attacks.a4_drift import execute_attack_a4_sequence
from bootsentry.attacks.a5_cross_sku import execute_attack_a5
from bootsentry.attacks.benign_controls import (
    execute_benign_cold_cache,
    execute_benign_cpu_load,
    execute_benign_firmware_upgrade,
)
from bootsentry.attacks.runner import run_attack_testbed

__all__ = [
    "execute_attack_a1",
    "execute_attack_a2",
    "execute_attack_a3",
    "execute_attack_a4_sequence",
    "execute_attack_a5",
    "execute_benign_cold_cache",
    "execute_benign_cpu_load",
    "execute_benign_firmware_upgrade",
    "run_attack_testbed",
]
