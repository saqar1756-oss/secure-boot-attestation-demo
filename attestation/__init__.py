"""Secure boot / remote attestation concept demo."""

from .boot_chain import ATTESTED_PCRS, BOOT_STAGES, BootChain, BootError
from .mock_tpm import (
    MockTPM,
    Quote,
    EventLogEntry,
    TPMError,
    canonical_quote_payload,
    verify_quote_signature,
)
from .policy import GoldenPolicy, PolicyError, build_policy_from_clean_boot
from .verifier import AttestationResult, Verifier

__all__ = [
    "ATTESTED_PCRS",
    "BOOT_STAGES",
    "AttestationResult",
    "BootChain",
    "BootError",
    "EventLogEntry",
    "GoldenPolicy",
    "MockTPM",
    "PolicyError",
    "Quote",
    "TPMError",
    "Verifier",
    "build_policy_from_clean_boot",
    "canonical_quote_payload",
    "verify_quote_signature",
]
