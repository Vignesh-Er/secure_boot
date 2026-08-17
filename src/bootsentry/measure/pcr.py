"""Software TPM-style Platform Configuration Register (PCR) Bank."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PcrBank:
    """Simulates a TPM 2.0 PCR Bank with SHA-256 hash extension."""

    num_registers: int = 8
    registers: Dict[int, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.registers:
            # Initialize all PCRs to 32 bytes of zeros (64 hex characters)
            zero_hash = "0" * 64
            self.registers = {i: zero_hash for i in range(self.num_registers)}

    def extend(self, pcr_index: int, measurement: bytes | str) -> str:
        """Extend PCR[index] with measurement: SHA256(current_pcr || measurement).

        Returns the new 64-char hex PCR value.
        """
        if pcr_index not in self.registers:
            raise IndexError(f"PCR index {pcr_index} is out of bounds (0..{self.num_registers - 1})")

        if isinstance(measurement, str):
            # If hex string of length 64, convert to bytes; else utf-8 encode
            if len(measurement) == 64 and all(c in "0123456789abcdefABCDEF" for c in measurement):
                meas_bytes = bytes.fromhex(measurement)
            else:
                meas_bytes = measurement.encode("utf-8")
        else:
            meas_bytes = measurement

        current_bytes = bytes.fromhex(self.registers[pcr_index])
        new_digest = hashlib.sha256(current_bytes + meas_bytes).hexdigest()
        self.registers[pcr_index] = new_digest
        return new_digest

    def read(self, pcr_index: int) -> str:
        """Read current value of PCR[index]."""
        if pcr_index not in self.registers:
            raise IndexError(f"PCR index {pcr_index} is out of bounds")
        return self.registers[pcr_index]

    def snapshot(self) -> Dict[int, str]:
        """Return a copy of the current PCR state."""
        return dict(self.registers)

    def composite_digest(self, selected_pcrs: Optional[List[int]] = None) -> str:
        """Calculate composite hash of selected PCRs (defaults to all)."""
        indices = selected_pcrs if selected_pcrs is not None else sorted(self.registers.keys())
        hasher = hashlib.sha256()
        for idx in indices:
            hasher.update(idx.to_bytes(4, "big"))
            hasher.update(bytes.fromhex(self.registers[idx]))
        return hasher.hexdigest()

    def to_dict(self) -> Dict[str, str]:
        """Serialize PCR bank to string-keyed dictionary."""
        return {f"PCR{k}": v for k, v in self.registers.items()}

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> PcrBank:
        """Construct PcrBank from serialized dictionary."""
        regs: Dict[int, str] = {}
        for k, v in data.items():
            idx = int(k.replace("PCR", ""))
            regs[idx] = v
        bank = cls(num_registers=max(8, len(regs)))
        bank.registers = regs
        return bank
