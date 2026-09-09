"""
Golden-value policy: the reference the verifier compares an attestation against.

This is the real-world Reference Integrity Manifest, in miniature.  It records,
for a known-good build:

  * the expected measurement (image digest) of every stage, and
  * the expected PCR value after that stage's extend.

Keeping the per-stage checkpoints, not just the final PCR value, is what lets
the verifier name WHICH stage failed instead of only reporting a mismatch.
Because a PCR is a hash chain, the first checkpoint that diverges is the first
stage that was tampered with; everything after it inherits the divergence.

Separating policy from measurement is also what makes patching survivable: a
legitimate update changes stage digests, and the operator re-issues the policy
without weakening anything about how measurement works.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .boot_chain import BOOT_STAGES, CHAIN_PCR, BootChain
from .mock_tpm import MockTPM

POLICY_VERSION = 1


class PolicyError(Exception):
    """Raised when a policy file is missing, malformed, or unusable."""


@dataclass(frozen=True)
class StageExpectation:
    stage: str
    pcr_index: int
    measurement: str  # expected image digest, hex
    pcr_after: str  # expected value of the stage's own PCR after its extend
    chain_after: str  # expected value of the shared chain PCR at this point


@dataclass(frozen=True)
class GoldenPolicy:
    """An ordered list of what a trustworthy boot must look like."""

    version: int
    stages: list[StageExpectation]

    def stage_names(self) -> list[str]:
        return [s.stage for s in self.stages]

    def final_pcrs(self) -> dict:
        return {s.pcr_index: s.pcr_after for s in self.stages}

    # -- serialisation -------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "stages": [
                {
                    "stage": s.stage,
                    "pcr_index": s.pcr_index,
                    "measurement": s.measurement,
                    "pcr_after": s.pcr_after,
                    "chain_after": s.chain_after,
                }
                for s in self.stages
            ],
        }

    def save(self, path: Path | str) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.to_dict(), indent=2) + "\n")

    @staticmethod
    def from_dict(d) -> "GoldenPolicy":
        if not isinstance(d, dict):
            raise PolicyError("policy must be a JSON object")
        try:
            version = int(d["version"])
            raw_stages = d["stages"]
        except (KeyError, TypeError, ValueError) as exc:
            raise PolicyError(f"policy missing required fields: {exc}") from exc

        if version != POLICY_VERSION:
            raise PolicyError(
                f"unsupported policy version {version}, expected {POLICY_VERSION}"
            )
        if not isinstance(raw_stages, list) or not raw_stages:
            raise PolicyError("policy must list at least one stage")

        stages = []
        for entry in raw_stages:
            if not isinstance(entry, dict):
                raise PolicyError("each policy stage must be an object")
            try:
                stages.append(
                    StageExpectation(
                        stage=str(entry["stage"]),
                        pcr_index=int(entry["pcr_index"]),
                        measurement=str(entry["measurement"]),
                        pcr_after=str(entry["pcr_after"]),
                        chain_after=str(entry["chain_after"]),
                    )
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise PolicyError(f"malformed policy stage: {exc}") from exc
        return GoldenPolicy(version=version, stages=stages)

    @staticmethod
    def load(path: Path | str) -> "GoldenPolicy":
        path = Path(path)
        try:
            raw = json.loads(path.read_text())
        except FileNotFoundError as exc:
            raise PolicyError(f"policy file not found: {path}") from exc
        except json.JSONDecodeError as exc:
            raise PolicyError(f"policy file is not valid JSON: {exc}") from exc
        return GoldenPolicy.from_dict(raw)


def build_policy_from_clean_boot(image_dir: Path | str) -> GoldenPolicy:
    """Derive a golden policy by booting a known-good image set once.

    In production the reference values come from the build pipeline that
    produced the images, signed by whoever vouches for them.  Deriving them
    from a local boot is a convenience for the demo, and is only safe because
    the image set is trusted at this moment by assumption.
    """
    reference_tpm = MockTPM()
    chain = BootChain(reference_tpm, image_dir)
    chain.boot()

    log = reference_tpm.event_log()
    # Each stage produces two log entries: one for its own register and one for
    # the shared chain register, so entries are keyed by (stage, pcr_index).
    by_key = {(entry.stage, entry.pcr_index): entry for entry in log}

    stages = []
    for stage, pcr_index in BOOT_STAGES:
        own = by_key.get((stage, pcr_index))
        chained = by_key.get((stage, CHAIN_PCR))
        if own is None:
            raise PolicyError(f"clean boot did not measure stage '{stage}'")
        if chained is None:
            raise PolicyError(
                f"clean boot did not extend stage '{stage}' into the chain register"
            )
        stages.append(
            StageExpectation(
                stage=stage,
                pcr_index=pcr_index,
                measurement=own.measurement,
                pcr_after=own.pcr_after,
                chain_after=chained.pcr_after,
            )
        )
    return GoldenPolicy(version=POLICY_VERSION, stages=stages)
