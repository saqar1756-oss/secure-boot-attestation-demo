"""
The remote verifier: the party that decides whether a node can be trusted.

It runs somewhere the node does not control, holds the AK public key and the
golden-value policy, and releases a secret only when an attestation passes
every check.

Check order matters and is deliberate — cheapest and most fundamental first,
so a forged or stale attestation is rejected before its contents are given any
weight:

  1. Structure       the quote and log are well-formed at all
  2. Freshness       the nonce is one we issued, and has not been used before
  3. Authenticity    the signature verifies under the AK public key
  4. Log consistency replaying the event log reproduces the SIGNED PCR values
  5. Policy          per-stage values match the golden policy

Step 4 is the one that is easy to leave out and fatal to omit.  The event log
arrives unsigned, so a compromised node could boot tampered code and then send
a pristine log.  Recomputing PCRs from the log and requiring the result to
equal the signed quote is what makes the log trustworthy — the log is believed
only because it agrees with something the TPM signed.

Every failure path returns UNTRUSTED and withholds the key.  There is no
branch that releases a secret on a partial pass.
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .boot_chain import CHAIN_PCR
from .mock_tpm import (
    DIGEST_LEN,
    PCR_RESET_VALUE,
    EventLogEntry,
    Quote,
    verify_quote_signature,
)
from .policy import GoldenPolicy

NONCE_BYTES = 32


@dataclass
class AttestationResult:
    """The verifier's verdict.  `trusted` is the only thing that gates the key."""

    trusted: bool
    reason: str
    failing_stage: str | None = None
    detail: dict = field(default_factory=dict)
    released_key: str | None = None

    def __str__(self) -> str:
        verdict = "TRUSTED" if self.trusted else "UNTRUSTED"
        if self.failing_stage:
            return f"{verdict} (failing stage: {self.failing_stage}) — {self.reason}"
        return f"{verdict} — {self.reason}"


class Verifier:
    """Issues challenges and judges the quotes that come back."""

    def __init__(
        self,
        policy: GoldenPolicy,
        ak_public: Ed25519PublicKey,
        node_secret: str = "workload-release-key-8f3a1c",
    ) -> None:
        self.policy = policy
        self.ak_public = ak_public
        self.node_secret = node_secret
        # Challenges we have issued and not yet consumed.  A nonce is removed
        # the first time it is presented, whatever the verdict, so a quote can
        # never be accepted twice.
        self._pending_nonces: set[str] = set()

    # -- challenge -----------------------------------------------------------

    def issue_challenge(self) -> str:
        """Generate a fresh random nonce and remember that we issued it."""
        nonce = secrets.token_bytes(NONCE_BYTES).hex()
        self._pending_nonces.add(nonce)
        return nonce

    # -- verification --------------------------------------------------------

    def verify(self, quote, event_log) -> AttestationResult:
        """Run all checks and return a verdict.  Never raises on bad input."""

        # --- 1. structure ---------------------------------------------------
        try:
            quote, entries = self._validate_structure(quote, event_log)
        except ValueError as exc:
            return AttestationResult(
                trusted=False, reason=f"malformed attestation: {exc}"
            )

        # --- 2. freshness ---------------------------------------------------
        # Consume the nonce whether or not the rest passes: a challenge is
        # single-use, so a captured quote cannot be replayed against it later.
        if quote.nonce not in self._pending_nonces:
            return AttestationResult(
                trusted=False,
                reason="nonce is stale, unknown, or already used — possible replay",
                detail={"nonce": quote.nonce},
            )
        self._pending_nonces.discard(quote.nonce)

        # --- 3. authenticity ------------------------------------------------
        if not verify_quote_signature(quote, self.ak_public):
            return AttestationResult(
                trusted=False,
                reason="quote signature is not valid under the expected AK",
            )

        # --- 4. log consistency ---------------------------------------------
        try:
            recomputed = self._replay_log(entries)
        except ValueError as exc:
            return AttestationResult(
                trusted=False, reason=f"event log could not be replayed: {exc}"
            )

        for pcr_index, signed_value in quote.pcr_values.items():
            computed = recomputed.get(pcr_index, PCR_RESET_VALUE.hex())
            if computed != signed_value:
                return AttestationResult(
                    trusted=False,
                    reason=(
                        f"event log does not reproduce the signed PCR{pcr_index} "
                        "value — the log has been substituted"
                    ),
                    detail={
                        "pcr_index": pcr_index,
                        "signed": signed_value,
                        "recomputed_from_log": computed,
                    },
                )

        # --- 5. policy ------------------------------------------------------
        return self._check_policy(entries, quote)

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _validate_structure(quote, event_log) -> tuple[Quote, list[EventLogEntry]]:
        """Coerce and sanity-check untrusted input. Raises ValueError if unusable."""
        if isinstance(quote, dict):
            try:
                quote = Quote.from_dict(quote)
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"quote fields missing or wrong type: {exc}") from exc
        if not isinstance(quote, Quote):
            raise ValueError("quote must be a Quote or a dict")

        if not isinstance(quote.pcr_values, dict) or not quote.pcr_values:
            raise ValueError("quote carries no PCR values")
        for idx, value in quote.pcr_values.items():
            if not isinstance(idx, int):
                raise ValueError("PCR index is not an integer")
            _require_hex(value, DIGEST_LEN, f"PCR{idx} value")
        _require_hex(quote.nonce, None, "nonce")
        _require_hex(quote.signature, 64, "signature")

        if event_log is None:
            raise ValueError("event log is missing")
        if not isinstance(event_log, (list, tuple)):
            raise ValueError("event log must be a list")

        entries: list[EventLogEntry] = []
        for i, item in enumerate(event_log):
            if isinstance(item, dict):
                try:
                    item = EventLogEntry.from_dict(item)
                except (KeyError, TypeError, ValueError) as exc:
                    raise ValueError(f"log entry {i} malformed: {exc}") from exc
            if not isinstance(item, EventLogEntry):
                raise ValueError(f"log entry {i} has unexpected type")
            _require_hex(item.measurement, DIGEST_LEN, f"log entry {i} measurement")
            _require_hex(item.pcr_after, DIGEST_LEN, f"log entry {i} pcr_after")
            entries.append(item)

        if not entries:
            raise ValueError("event log is empty")
        return quote, entries

    @staticmethod
    def _replay_log(entries: list[EventLogEntry]) -> dict:
        """Recompute PCR values from the log using the same extend rule.

        Starts from the power-on reset value, exactly as the device does.
        """
        pcrs: dict[int, bytes] = {}
        for entry in entries:
            current = pcrs.get(entry.pcr_index, PCR_RESET_VALUE)
            try:
                measurement = bytes.fromhex(entry.measurement)
            except ValueError as exc:
                raise ValueError(f"bad measurement hex in stage {entry.stage}") from exc
            pcrs[entry.pcr_index] = hashlib.sha256(current + measurement).digest()
        return {idx: value.hex() for idx, value in pcrs.items()}

    def _check_policy(
        self, entries: list[EventLogEntry], quote: Quote
    ) -> AttestationResult:
        """Compare the boot against the golden policy, stage by stage, in order.

        The first divergence names the failing stage.  Later stages will also
        mismatch — that is the hash chain propagating — but they are effects,
        not the cause, so only the first is reported.
        """
        expected_stages = self.policy.stages
        # Two entries per stage (own register + chain register), so key on both.
        logged = {(entry.stage, entry.pcr_index): entry for entry in entries}

        for expectation in expected_stages:
            entry = logged.get((expectation.stage, expectation.pcr_index))
            chain_entry = logged.get((expectation.stage, CHAIN_PCR))

            if entry is None:
                return AttestationResult(
                    trusted=False,
                    reason=(
                        f"stage '{expectation.stage}' was never measured into "
                        f"PCR{expectation.pcr_index}"
                    ),
                    failing_stage=expectation.stage,
                )

            if chain_entry is None:
                return AttestationResult(
                    trusted=False,
                    reason=(
                        f"stage '{expectation.stage}' was not extended into the "
                        f"chain register PCR{CHAIN_PCR}"
                    ),
                    failing_stage=expectation.stage,
                )

            # The aggregate is the check that cannot be dodged: because every
            # stage extends into it, a tamper anywhere changes it here and at
            # every later stage.
            if chain_entry.pcr_after != expectation.chain_after:
                return AttestationResult(
                    trusted=False,
                    reason=(
                        f"aggregate chain value diverges at stage "
                        f"'{expectation.stage}'"
                    ),
                    failing_stage=expectation.stage,
                    detail={
                        "expected_chain": expectation.chain_after,
                        "actual_chain": chain_entry.pcr_after,
                    },
                )

            if entry.measurement != expectation.measurement:
                return AttestationResult(
                    trusted=False,
                    reason=f"stage '{expectation.stage}' does not match its golden measurement",
                    failing_stage=expectation.stage,
                    detail={
                        "expected_measurement": expectation.measurement,
                        "actual_measurement": entry.measurement,
                    },
                )

            signed_pcr = quote.pcr_values.get(expectation.pcr_index)
            if signed_pcr != expectation.pcr_after:
                return AttestationResult(
                    trusted=False,
                    reason=(
                        f"PCR{expectation.pcr_index} after stage "
                        f"'{expectation.stage}' does not match the golden value"
                    ),
                    failing_stage=expectation.stage,
                    detail={
                        "expected_pcr": expectation.pcr_after,
                        "actual_pcr": signed_pcr,
                    },
                )

        # Reject anything measured that the policy does not account for, rather
        # than ignoring it — an unexpected extra measurement is unexplained code
        # that would otherwise slip through by not being looked for.
        allowed = {(s.stage, s.pcr_index) for s in expected_stages}
        allowed |= {(s.stage, CHAIN_PCR) for s in expected_stages}
        unexpected = [
            f"{e.stage}->PCR{e.pcr_index}"
            for e in entries
            if (e.stage, e.pcr_index) not in allowed
        ]
        if unexpected:
            return AttestationResult(
                trusted=False,
                reason=f"unexpected measurement(s): {', '.join(unexpected)}",
                failing_stage=entries[0].stage if entries else None,
            )

        return AttestationResult(
            trusted=True,
            reason="all stages match the golden policy; quote is fresh and authentic",
            released_key=self.node_secret,
        )


def _require_hex(value, expected_len_bytes, label: str) -> None:
    """Validate that `value` is a hex string, optionally of a fixed byte length."""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be a string")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise ValueError(f"{label} is not valid hex") from exc
    if expected_len_bytes is not None and len(raw) != expected_len_bytes:
        raise ValueError(
            f"{label} must be {expected_len_bytes} bytes, got {len(raw)}"
        )
