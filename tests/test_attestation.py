"""
Test suite for the boot-attestation chain.

Grouped by what is being defended:
  * TPM register semantics  — the maths must be right or nothing above it holds
  * Boot chain              — measure-before-execute, ordering
  * Verifier happy path     — a clean boot is accepted
  * Attack scenarios        — tamper, replay, forgery, log substitution
  * Robustness              — malformed input, repeat runs
"""

from __future__ import annotations

import hashlib
import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from attestation import (  # noqa: E402
    BootChain,
    GoldenPolicy,
    MockTPM,
    PolicyError,
    Quote,
    TPMError,
    Verifier,
    build_policy_from_clean_boot,
)
from attestation.boot_chain import (  # noqa: E402
    ATTESTED_PCRS,
    BOOT_STAGES,
    CHAIN_PCR,
    BootError,
)
from attestation.mock_tpm import (  # noqa: E402
    DIGEST_LEN,
    PCR_RESET_VALUE,
    canonical_quote_payload,
)
from make_images import write_clean_images  # noqa: E402


# --- fixtures ---------------------------------------------------------------


@pytest.fixture
def images(tmp_path) -> Path:
    """A pristine, isolated copy of the stage images for each test."""
    source = Path(__file__).resolve().parent.parent / "images"
    write_clean_images(source)
    workdir = tmp_path / "images"
    shutil.copytree(source, workdir)
    return workdir


@pytest.fixture
def policy(images) -> GoldenPolicy:
    return build_policy_from_clean_boot(images)


@pytest.fixture
def booted(images):
    """A TPM that has completed a clean boot."""
    tpm = MockTPM()
    BootChain(tpm, images).boot()
    return tpm


def attest(tpm, verifier):
    nonce = verifier.issue_challenge()
    quote = tpm.quote(nonce, indices=ATTESTED_PCRS)
    return verifier.verify(quote, tpm.event_log())


# --- TPM register semantics -------------------------------------------------


class TestPCRSemantics:
    def test_pcrs_start_at_reset_value(self):
        tpm = MockTPM()
        assert tpm.read_pcr(0) == PCR_RESET_VALUE

    def test_extend_matches_the_defining_equation(self):
        """PCR_new must equal H(PCR_old || measurement), exactly."""
        tpm = MockTPM()
        measurement = hashlib.sha256(b"stage-image").digest()
        expected = hashlib.sha256(PCR_RESET_VALUE + measurement).digest()
        assert tpm.extend(0, measurement, "test") == expected

    def test_extend_is_order_dependent(self):
        """Extending A then B must differ from B then A."""
        a = hashlib.sha256(b"A").digest()
        b = hashlib.sha256(b"B").digest()

        first, second = MockTPM(), MockTPM()
        first.extend(0, a, "a")
        first.extend(0, b, "b")
        second.extend(0, b, "b")
        second.extend(0, a, "a")

        assert first.read_pcr(0) != second.read_pcr(0)

    def test_extend_is_not_reversible(self):
        """No sequence of later extends restores an earlier PCR value."""
        tpm = MockTPM()
        clean = hashlib.sha256(b"clean").digest()
        tpm.extend(0, clean, "clean")
        target = tpm.read_pcr(0)

        tpm.power_cycle()
        tpm.extend(0, hashlib.sha256(b"tampered").digest(), "tampered")
        for i in range(50):
            tpm.extend(0, hashlib.sha256(f"try{i}".encode()).digest(), "try")
            assert tpm.read_pcr(0) != target

    def test_no_api_to_set_a_pcr_directly(self):
        tpm = MockTPM()
        assert not hasattr(tpm, "set_pcr")
        assert not hasattr(tpm, "write_pcr")

    def test_power_cycle_resets_all_pcrs_and_log(self):
        tpm = MockTPM()
        tpm.extend(0, hashlib.sha256(b"x").digest(), "x")
        tpm.power_cycle()
        assert tpm.read_pcr(0) == PCR_RESET_VALUE
        assert tpm.event_log() == []

    def test_extend_rejects_wrong_length_measurement(self):
        tpm = MockTPM()
        with pytest.raises(TPMError):
            tpm.extend(0, b"too-short", "bad")

    def test_extend_rejects_bad_index(self):
        tpm = MockTPM()
        digest = hashlib.sha256(b"x").digest()
        for bad in (-1, 999, "0", None):
            with pytest.raises(TPMError):
                tpm.extend(bad, digest, "bad")

    def test_private_key_is_not_exposed(self):
        tpm = MockTPM()
        public_attrs = [a for a in dir(tpm) if not a.startswith("_")]
        assert not any("private" in a for a in public_attrs)


class TestQuote:
    def test_quote_signature_verifies(self, booted):
        from attestation import verify_quote_signature

        quote = booted.quote("ab" * 16, indices=ATTESTED_PCRS)
        assert verify_quote_signature(quote, booted.ak_public_key())

    def test_quote_is_bound_to_the_nonce(self, booted):
        """Changing only the nonce must invalidate the signature."""
        from attestation import verify_quote_signature

        quote = booted.quote("ab" * 16, indices=ATTESTED_PCRS)
        swapped = Quote(
            pcr_values=quote.pcr_values,
            nonce="cd" * 16,
            signature=quote.signature,
            algorithm=quote.algorithm,
        )
        assert not verify_quote_signature(swapped, booted.ak_public_key())

    def test_quote_is_bound_to_pcr_values(self, booted):
        from attestation import verify_quote_signature

        quote = booted.quote("ab" * 16, indices=ATTESTED_PCRS)
        tampered_pcrs = dict(quote.pcr_values)
        tampered_pcrs[0] = "00" * DIGEST_LEN
        swapped = Quote(
            pcr_values=tampered_pcrs,
            nonce=quote.nonce,
            signature=quote.signature,
            algorithm=quote.algorithm,
        )
        assert not verify_quote_signature(swapped, booted.ak_public_key())

    def test_different_ak_produces_unverifiable_quote(self, booted):
        from attestation import verify_quote_signature

        rogue = MockTPM()
        quote = booted.quote("ab" * 16, indices=ATTESTED_PCRS)
        assert not verify_quote_signature(quote, rogue.ak_public_key())

    def test_short_nonce_is_refused(self, booted):
        with pytest.raises(TPMError):
            booted.quote("ab")

    def test_canonical_payload_is_order_independent(self):
        """Dict ordering must not change what gets signed."""
        a = canonical_quote_payload({0: "aa", 1: "bb"}, "cc")
        b = canonical_quote_payload({1: "bb", 0: "aa"}, "cc")
        assert a == b

    def test_canonical_payload_separates_fields(self):
        """Field boundaries must be unambiguous."""
        a = canonical_quote_payload({0: "aabb"}, "cc")
        b = canonical_quote_payload({0: "aa"}, "bbcc")
        assert a != b


# --- boot chain -------------------------------------------------------------


class TestBootChain:
    def test_all_stages_measured_in_order(self, booted):
        own_entries = [
            e for e in booted.event_log() if e.pcr_index != CHAIN_PCR
        ]
        assert [e.stage for e in own_entries] == [s for s, _ in BOOT_STAGES]

    def test_each_stage_extends_own_and_chain_register(self, booted):
        log = booted.event_log()
        for stage, pcr_index in BOOT_STAGES:
            assert any(e.stage == stage and e.pcr_index == pcr_index for e in log)
            assert any(e.stage == stage and e.pcr_index == CHAIN_PCR for e in log)

    def test_measurement_reflects_image_contents(self, images):
        tpm = MockTPM()
        chain = BootChain(tpm, images)
        expected = hashlib.sha256((images / "kernel.img").read_bytes()).digest()
        assert chain.measure("kernel") == expected

    def test_missing_image_raises_boot_error(self, images):
        (images / "kernel.img").unlink()
        with pytest.raises(BootError):
            BootChain(MockTPM(), images).boot()

    def test_boot_is_deterministic(self, images):
        """Same images must produce the same PCR values every time."""
        first, second = MockTPM(), MockTPM()
        BootChain(first, images).boot()
        BootChain(second, images).boot()
        assert first.pcr_values(ATTESTED_PCRS) == second.pcr_values(ATTESTED_PCRS)

    def test_rebooting_same_tpm_reproduces_values(self, images):
        """A second boot on the same device must not accumulate state."""
        tpm = MockTPM()
        chain = BootChain(tpm, images)
        chain.boot()
        first = tpm.pcr_values(ATTESTED_PCRS)
        chain.boot()
        assert tpm.pcr_values(ATTESTED_PCRS) == first


# --- verifier happy path ----------------------------------------------------


class TestCleanBoot:
    def test_clean_boot_is_trusted(self, booted, policy):
        verifier = Verifier(policy, booted.ak_public_key())
        result = attest(booted, verifier)
        assert result.trusted
        assert result.failing_stage is None

    def test_key_released_only_when_trusted(self, booted, policy):
        verifier = Verifier(policy, booted.ak_public_key())
        assert attest(booted, verifier).released_key == verifier.node_secret

    def test_repeated_attestations_all_succeed(self, booted, policy):
        """Each fresh challenge must independently succeed."""
        verifier = Verifier(policy, booted.ak_public_key())
        for _ in range(5):
            assert attest(booted, verifier).trusted


# --- attack scenarios -------------------------------------------------------


class TestTampering:
    @pytest.mark.parametrize("stage", [s for s, _ in BOOT_STAGES])
    def test_tampering_any_stage_is_caught_and_attributed(
        self, images, policy, stage
    ):
        """Every stage, tampered in turn, must be named as the failing stage."""
        target = images / f"{stage}.img"
        target.write_text(target.read_text() + "\nTAMPERED\n")

        tpm = MockTPM()
        BootChain(tpm, images).boot()
        verifier = Verifier(policy, tpm.ak_public_key())
        result = attest(tpm, verifier)

        assert not result.trusted
        assert result.failing_stage == stage
        assert result.released_key is None

    def test_single_byte_change_is_detected(self, images, policy):
        target = images / "kernel.img"
        data = bytearray(target.read_bytes())
        data[0] ^= 0x01  # flip one bit
        target.write_bytes(bytes(data))

        tpm = MockTPM()
        BootChain(tpm, images).boot()
        verifier = Verifier(policy, tpm.ak_public_key())
        result = attest(tpm, verifier)
        assert not result.trusted
        assert result.failing_stage == "kernel"

    def test_tamper_propagates_through_chain_register(self, images, policy):
        """A mid-chain tamper must change the aggregate at every later stage."""
        target = images / "kernel.img"
        target.write_text(target.read_text() + "\nTAMPERED\n")

        tpm = MockTPM()
        BootChain(tpm, images).boot()
        chain_after = {
            e.stage: e.pcr_after
            for e in tpm.event_log()
            if e.pcr_index == CHAIN_PCR
        }
        golden = {s.stage: s.chain_after for s in policy.stages}

        # before the tamper: identical
        assert chain_after["firmware"] == golden["firmware"]
        assert chain_after["bootloader"] == golden["bootloader"]
        # from the tamper onward: never recovers
        for stage in ("kernel", "os", "ai_runtime"):
            assert chain_after[stage] != golden[stage]

    def test_earlier_stages_still_match_after_later_tamper(self, images, policy):
        """Tampering the last stage must not implicate earlier ones."""
        target = images / "ai_runtime.img"
        target.write_text(target.read_text() + "\nTAMPERED\n")

        tpm = MockTPM()
        BootChain(tpm, images).boot()
        verifier = Verifier(policy, tpm.ak_public_key())
        result = attest(tpm, verifier)
        assert result.failing_stage == "ai_runtime"


class TestForgery:
    def test_replayed_quote_is_rejected(self, booted, policy):
        """A captured quote must not satisfy a later challenge."""
        verifier = Verifier(policy, booted.ak_public_key())

        nonce = verifier.issue_challenge()
        captured = booted.quote(nonce, indices=ATTESTED_PCRS)
        log = booted.event_log()
        assert verifier.verify(captured, log).trusted  # legitimate first use

        verifier.issue_challenge()  # fresh challenge issued
        replayed = verifier.verify(captured, log)
        assert not replayed.trusted
        assert "replay" in replayed.reason.lower()

    def test_nonce_is_single_use(self, booted, policy):
        """Even without a new challenge, a nonce cannot be reused."""
        verifier = Verifier(policy, booted.ak_public_key())
        nonce = verifier.issue_challenge()
        quote = booted.quote(nonce, indices=ATTESTED_PCRS)
        log = booted.event_log()

        assert verifier.verify(quote, log).trusted
        assert not verifier.verify(quote, log).trusted

    def test_unissued_nonce_is_rejected(self, booted, policy):
        """A node cannot choose its own nonce."""
        verifier = Verifier(policy, booted.ak_public_key())
        quote = booted.quote("ab" * 32, indices=ATTESTED_PCRS)
        assert not verifier.verify(quote, booted.event_log()).trusted

    def test_quote_signed_by_wrong_key_is_rejected(self, booted, policy):
        verifier = Verifier(policy, booted.ak_public_key())
        rogue = MockTPM()
        BootChain(rogue, Path(__file__).resolve().parent.parent / "images")

        nonce = verifier.issue_challenge()
        forged = Quote(
            pcr_values=booted.pcr_values(ATTESTED_PCRS),  # correct values
            nonce=nonce,  # fresh nonce
            signature=rogue.quote(nonce, indices=ATTESTED_PCRS).signature,
            algorithm="sha256",
        )
        result = verifier.verify(forged, booted.event_log())
        assert not result.trusted
        assert "signature" in result.reason.lower()

    def test_substituted_clean_log_is_rejected(self, images, policy):
        """A tampered node cannot send someone else's clean event log."""
        clean_tpm = MockTPM()
        BootChain(clean_tpm, images).boot()
        clean_log = clean_tpm.event_log()

        target = images / "kernel.img"
        target.write_text(target.read_text() + "\nTAMPERED\n")
        tampered_tpm = MockTPM()
        BootChain(tampered_tpm, images).boot()

        verifier = Verifier(policy, tampered_tpm.ak_public_key())
        nonce = verifier.issue_challenge()
        truthful_quote = tampered_tpm.quote(nonce, indices=ATTESTED_PCRS)

        result = verifier.verify(truthful_quote, clean_log)
        assert not result.trusted
        assert "log" in result.reason.lower()

    def test_forged_log_matching_forged_quote_still_fails_policy(
        self, images, policy
    ):
        """Consistent-but-wrong evidence must still fail the golden check."""
        target = images / "kernel.img"
        target.write_text(target.read_text() + "\nTAMPERED\n")
        tpm = MockTPM()
        BootChain(tpm, images).boot()

        verifier = Verifier(policy, tpm.ak_public_key())
        result = attest(tpm, verifier)  # internally consistent, but tampered
        assert not result.trusted
        assert result.failing_stage == "kernel"


# --- robustness -------------------------------------------------------------


class TestMalformedInput:
    @pytest.mark.parametrize(
        "quote,log",
        [
            (None, []),
            ("not-a-quote", []),
            (12345, []),
            ({}, []),
            ({"pcr_values": {}, "nonce": "aa" * 16, "signature": "bb" * 64}, []),
            ({"pcr_values": {"0": "zz"}, "nonce": "aa" * 16, "signature": "bb" * 64}, []),
            ({"pcr_values": {"0": "00" * 32}, "nonce": "!!", "signature": "bb" * 64}, []),
            ({"pcr_values": {"0": "00" * 32}, "nonce": "aa" * 16, "signature": "bb"}, []),
            ({"pcr_values": {"0": "00" * 32}, "nonce": "aa" * 16, "signature": "bb" * 64}, None),
            ({"pcr_values": {"0": "00" * 32}, "nonce": "aa" * 16, "signature": "bb" * 64}, "str"),
            ({"pcr_values": {"0": "00" * 32}, "nonce": "aa" * 16, "signature": "bb" * 64}, [None]),
            ({"pcr_values": {"0": "00" * 32}, "nonce": "aa" * 16, "signature": "bb" * 64},
             [{"pcr_index": "x", "stage": "s", "measurement": "00" * 32, "pcr_after": "00" * 32}]),
        ],
    )
    def test_verifier_fails_closed_without_raising(self, policy, booted, quote, log):
        verifier = Verifier(policy, booted.ak_public_key())
        result = verifier.verify(quote, log)  # must not raise
        assert not result.trusted
        assert result.released_key is None

    def test_empty_log_rejected(self, booted, policy):
        verifier = Verifier(policy, booted.ak_public_key())
        nonce = verifier.issue_challenge()
        quote = booted.quote(nonce, indices=ATTESTED_PCRS)
        assert not verifier.verify(quote, []).trusted

    def test_extra_unexpected_measurement_rejected(self, images, policy):
        """Code measured but absent from policy must not be ignored."""
        tpm = MockTPM()
        BootChain(tpm, images).boot()
        tpm.extend(5, hashlib.sha256(b"rogue-module").digest(), "rogue_module")

        verifier = Verifier(policy, tpm.ak_public_key())
        result = attest(tpm, verifier)
        assert not result.trusted


class TestPolicy:
    def test_policy_round_trips_through_disk(self, policy, tmp_path):
        path = tmp_path / "golden.json"
        policy.save(path)
        assert GoldenPolicy.load(path).to_dict() == policy.to_dict()

    def test_malformed_policy_file_rejected(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("{not json")
        with pytest.raises(PolicyError):
            GoldenPolicy.load(path)

    def test_missing_policy_file_rejected(self, tmp_path):
        with pytest.raises(PolicyError):
            GoldenPolicy.load(tmp_path / "nope.json")

    def test_wrong_version_rejected(self, policy, tmp_path):
        data = policy.to_dict()
        data["version"] = 99
        path = tmp_path / "v99.json"
        path.write_text(__import__("json").dumps(data))
        with pytest.raises(PolicyError):
            GoldenPolicy.load(path)

    def test_policy_covers_every_stage(self, policy):
        assert policy.stage_names() == [s for s, _ in BOOT_STAGES]
