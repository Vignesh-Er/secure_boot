"""Boot subsystem exports."""

from bootsentry.boot.handoff import BootHandoff
from bootsentry.boot.runner import (
    BootExecutionResult,
    execute_boot_chain,
    initialize_default_environment,
)
from bootsentry.boot.s0_bootrom import run_stage_0
from bootsentry.boot.s1_bootloader import run_stage_1
from bootsentry.boot.s2_kernel import run_stage_2
from bootsentry.boot.s3_init import run_stage_3
from bootsentry.boot.services import DEFAULT_SERVICE_SEQUENCE, SERVICE_REGISTRY

__all__ = [
    "BootExecutionResult",
    "BootHandoff",
    "DEFAULT_SERVICE_SEQUENCE",
    "SERVICE_REGISTRY",
    "execute_boot_chain",
    "initialize_default_environment",
    "run_stage_0",
    "run_stage_1",
    "run_stage_2",
    "run_stage_3",
]
