"""
Mock TPM 2.0 — PCR bank, extend semantics, and a signed quote operation.

Models the parts of a TPM that matter for measured boot and remote
attestation.  What is faithfully reproduced:

  * PCRs are append-only accumulators, not storage.  The only way to change
    a PCR is extend(), which computes  PCR_new = H(PCR_old || measurement).
  * PCRs reset only on a simulated power cycle, never to an arbitrary value.
  * The attestation key (AK) private half is never exposed by the public
    interface; signing happens "inside" the device.
  * A quote signs the PCR values together with a caller-supplied nonce, so
    the signature is bound to one specific challenge.

What is NOT reproduced (see README, "What this does not prove"): hardware
isolation.  A real TPM's guarantees come from being separate silicon; this
object lives in the same process as its caller.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Iterable

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# --- device constants -------------------------------------------------------

DIGEST_ALG = "sha256"
DIGEST_LEN = 32
NUM_PCRS = 8
PCR_RESET_VALUE = b"\x00" * DIGEST_LEN

# Version tag for the signed payload.  Including a domain-separation string
# stops a signature made over some other structure from being reinterpreted
# as a quote.
QUOTE_PAYLOAD_TAG = b"MOCKTPM-QUOTE-v1"


class TPMError(Exception):
    """Raised when the device is asked to do something it must refuse."""


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# --- data carried off the device --------------------------------------------


@dataclass(frozen=True)
class EventLogEntry:
    """One measurement, as recorded in the (unsigned) TCG-style event log.

    The event log is a convenience for the verifier: it is NOT trusted on its
    own.  The verifier replays it to recompute PCR values and only believes it
    if the result matches the signed quote.
    """

    pcr_index: int
    stage: str
    measurement: str  # hex digest of the measured image
    pcr_after: str  # hex PCR value after this extend, for readability

    def to_dict(self) -> dict:
        return {
            "pcr_index": self.pcr_index,
            "stage": self.stage,
            "measurement": self.measurement,
            "pcr_after": self.pcr_after,
        }

    @staticmethod
    def from_dict(d: dict) -> "EventLogEntry":
        return EventLogEntry(
            pcr_index=int(d["pcr_index"]),
            stage=str(d["stage"]),
            measurement=str(d["measurement"]),
            pcr_after=str(d["pcr_after"]),
        )


@dataclass(frozen=True)
class Quote:
    """A signed attestation statement produced by quote()."""

    pcr_values: dict  # {pcr_index (int): hex digest (str)}
    nonce: str  # hex, supplied by the verifier
    signature: str  # hex Ed25519 signature over the canonical payload
    algorithm: str = DIGEST_ALG

    def to_dict(self) -> dict:
        return {
            "pcr_values": {str(k): v for k, v in sorted(self.pcr_values.items())},
            "nonce": self.nonce,
            "signature": self.signature,
            "algorithm": self.algorithm,
        }

    @staticmethod
    def from_dict(d: dict) -> "Quote":
        return Quote(
            pcr_values={int(k): str(v) for k, v in d["pcr_values"].items()},
            nonce=str(d["nonce"]),
            signature=str(d["signature"]),
            algorithm=str(d.get("algorithm", DIGEST_ALG)),
        )


def canonical_quote_payload(
    pcr_values: dict, nonce_hex: str, algorithm: str = DIGEST_ALG
) -> bytes:
    """Deterministic byte encoding of what a quote signs.

    Both the TPM (when signing) and the verifier (when checking) build this
    the same way.  PCR indices are sorted so the encoding cannot vary with
    dict ordering, and fields are length-delimited by separators that cannot
    appear inside hex digests, so no two distinct inputs share an encoding.
    """
    pcr_part = ",".join(f"{idx}:{pcr_values[idx]}" for idx in sorted(pcr_values))
    return b"|".join(
        [
            QUOTE_PAYLOAD_TAG,
            algorithm.encode("ascii"),
            pcr_part.encode("ascii"),
            nonce_hex.encode("ascii"),
        ]
    )


# --- the device -------------------------------------------------------------


class MockTPM:
    """A simulated TPM.  One instance == one machine's security chip."""

    def __init__(self, ak_private: Ed25519PrivateKey | None = None) -> None:
        # The AK is generated once, at "manufacture".  A real TPM derives it
        # from a burned-in Endorsement Key; the private half never leaves the
        # chip, which is why this attribute is private and has no getter.
        self.__ak_private = ak_private or Ed25519PrivateKey.generate()
        self._pcrs: list[bytes] = [PCR_RESET_VALUE] * NUM_PCRS
        self._event_log: list[EventLogEntry] = []

    # -- power ---------------------------------------------------------------

    def power_cycle(self) -> None:
        """Reset PCRs to their power-on value and clear the event log.

        This is the ONLY operation that returns a PCR to a known value, and it
        clears every PCR at once.  There is deliberately no way to reset or
        assign a single PCR: that is what makes the register append-only.
        """
        self._pcrs = [PCR_RESET_VALUE] * NUM_PCRS
        self._event_log = []

    # -- measurement ---------------------------------------------------------

    def extend(self, pcr_index: int, measurement: bytes, stage: str) -> bytes:
        """PCR_new = H(PCR_old || measurement).  Returns the new PCR value.

        Order-dependent and irreversible: extending A then B gives a different
        result from B then A, and no later extend can undo an earlier one.
        """
        self._check_index(pcr_index)
        if not isinstance(measurement, (bytes, bytearray)):
            raise TPMError("measurement must be bytes")
        if len(measurement) != DIGEST_LEN:
            raise TPMError(
                f"measurement must be a {DIGEST_LEN}-byte {DIGEST_ALG} digest, "
                f"got {len(measurement)} bytes"
            )

        old = self._pcrs[pcr_index]
        new = sha256(old + bytes(measurement))
        self._pcrs[pcr_index] = new

        self._event_log.append(
            EventLogEntry(
                pcr_index=pcr_index,
                stage=stage,
                measurement=bytes(measurement).hex(),
                pcr_after=new.hex(),
            )
        )
        return new

    def read_pcr(self, pcr_index: int) -> bytes:
        self._check_index(pcr_index)
        return self._pcrs[pcr_index]

    def pcr_values(self, indices: Iterable[int] | None = None) -> dict:
        """Current PCR values as {index: hex}."""
        if indices is None:
            indices = range(NUM_PCRS)
        result = {}
        for i in indices:
            self._check_index(i)
            result[i] = self._pcrs[i].hex()
        return result

    def event_log(self) -> list[EventLogEntry]:
        """A copy of the measurement log, for sending alongside a quote."""
        return list(self._event_log)

    # -- attestation ---------------------------------------------------------

    def quote(self, nonce: bytes | str, indices: Iterable[int] | None = None) -> Quote:
        """Sign the selected PCR values together with the verifier's nonce.

        The nonce is what makes the quote fresh: a quote captured from an
        earlier boot carries an old nonce and will not satisfy a new challenge.
        """
        nonce_hex = self._normalise_nonce(nonce)
        pcrs = self.pcr_values(indices)
        payload = canonical_quote_payload(pcrs, nonce_hex, DIGEST_ALG)
        signature = self.__ak_private.sign(payload)
        return Quote(
            pcr_values=pcrs,
            nonce=nonce_hex,
            signature=signature.hex(),
            algorithm=DIGEST_ALG,
        )

    def ak_public_key(self) -> Ed25519PublicKey:
        """The AK public half — the only key material that leaves the device."""
        return self.__ak_private.public_key()

    # -- internals -----------------------------------------------------------

    @staticmethod
    def _check_index(pcr_index) -> None:
        if not isinstance(pcr_index, int) or isinstance(pcr_index, bool):
            raise TPMError(f"PCR index must be an int, got {type(pcr_index).__name__}")
        if not 0 <= pcr_index < NUM_PCRS:
            raise TPMError(f"PCR index {pcr_index} out of range 0..{NUM_PCRS - 1}")

    @staticmethod
    def _normalise_nonce(nonce: bytes | str) -> str:
        if isinstance(nonce, (bytes, bytearray)):
            nonce_hex = bytes(nonce).hex()
        elif isinstance(nonce, str):
            try:
                bytes.fromhex(nonce)
            except ValueError as exc:
                raise TPMError("nonce string must be hex") from exc
            nonce_hex = nonce.lower()
        else:
            raise TPMError("nonce must be bytes or a hex string")
        if len(nonce_hex) < 32:  # 16 bytes minimum
            raise TPMError("nonce too short; refusing to sign a weak challenge")
        return nonce_hex


def verify_quote_signature(
    quote: Quote, ak_public: Ed25519PublicKey
) -> bool:
    """Check a quote's signature against an AK public key.

    Lives outside MockTPM because verification is the *verifier's* job and
    needs no access to the device.
    """
    try:
        payload = canonical_quote_payload(
            quote.pcr_values, quote.nonce, quote.algorithm
        )
        ak_public.verify(bytes.fromhex(quote.signature), payload)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
