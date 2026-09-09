"""
A simulated measured boot chain: firmware -> bootloader -> kernel -> os -> ai_runtime.

The rule every stage follows is the one that makes a chain of trust work:

    measure the next stage, THEN transfer control to it

Measuring first is what closes the gap a malicious stage would otherwise use.
By the time a tampered stage is running and could try to hide itself, its
digest is already committed to a PCR, and no later extend can remove it.

Trust is transitive backwards along this chain and bottoms out at the firmware,
which cannot be measured by anything earlier.  In hardware that role belongs to
an immutable boot ROM (the Core Root of Trust for Measurement); here the
firmware self-measures, and that self-measurement is exactly the assumption the
simulation cannot justify on its own.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .mock_tpm import MockTPM, sha256

# Stage name -> PCR index.  Loosely mirrors the TCG PC Client convention of
# giving firmware, loader and OS components their own registers rather than
# piling everything into one.
BOOT_STAGES: list[tuple[str, int]] = [
    ("firmware", 0),
    ("bootloader", 1),
    ("kernel", 2),
    ("os", 3),
    ("ai_runtime", 4),
]

# Every stage is ALSO extended into one shared aggregate register.
#
# Why both:  per-stage PCRs give attribution — PCR2 diverging points straight at
# the kernel.  But per-stage registers are independent of one another, so a
# kernel tamper leaves PCR3 and PCR4 looking perfectly normal.  Only a register
# that every stage extends into produces the property measured boot actually
# relies on: because  PCR_new = H(PCR_old || measurement),  changing any one
# stage changes the aggregate from that point forward, and no later stage can
# extend its way back to the expected value.
#
# This mirrors real TPM practice, where PCR7 aggregates secure-boot state rather
# than each component being trusted to its own register alone.
CHAIN_PCR = 7

ATTESTED_PCRS = [idx for _, idx in BOOT_STAGES] + [CHAIN_PCR]


class BootError(Exception):
    """Raised when the chain cannot proceed (e.g. a stage image is missing)."""


@dataclass
class BootResult:
    completed: bool
    stages_executed: list[str]
    measurements: dict  # stage -> hex digest


class BootChain:
    """Drives the simulated boot, extending a PCR per stage as it goes."""

    def __init__(self, tpm: MockTPM, image_dir: Path | str) -> None:
        self.tpm = tpm
        self.image_dir = Path(image_dir)

    def image_path(self, stage: str) -> Path:
        return self.image_dir / f"{stage}.img"

    def measure(self, stage: str) -> bytes:
        """Hash a stage image. This stands in for hashing a real binary."""
        path = self.image_path(stage)
        try:
            data = path.read_bytes()
        except FileNotFoundError as exc:
            raise BootError(f"stage image missing: {path}") from exc
        except OSError as exc:
            raise BootError(f"cannot read stage image {path}: {exc}") from exc
        return sha256(data)

    def boot(self) -> BootResult:
        """Run the chain from a power cycle to the final stage.

        Note the ordering inside the loop: the measurement of stage N+1 is
        committed to the TPM by stage N *before* stage N+1 is allowed to run.
        """
        self.tpm.power_cycle()

        executed: list[str] = []
        measurements: dict = {}

        for stage, pcr_index in BOOT_STAGES:
            # --- current stage acts as the loader for this image ---
            digest = self.measure(stage)  # 1. measure

            # 2. commit, twice: once to the stage's own register (attribution)
            #    and once to the shared chain register (propagation).  Order is
            #    fixed and must match how the verifier replays the log.
            self.tpm.extend(pcr_index, digest, stage)
            self.tpm.extend(CHAIN_PCR, digest, stage)

            measurements[stage] = digest.hex()

            self._execute(stage)  # 3. only now, hand over control
            executed.append(stage)

        return BootResult(
            completed=True, stages_executed=executed, measurements=measurements
        )

    @staticmethod
    def _execute(stage: str) -> None:
        """Stand-in for transferring control to the measured stage.

        Deliberately does nothing: the simulation is about what gets measured
        and in what order, not about emulating firmware behaviour.  A tampered
        image still 'runs' here — the point is that the verifier rejects it
        afterwards, not that this function refuses to execute it.
        """
        return None
