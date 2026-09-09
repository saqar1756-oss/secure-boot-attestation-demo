#!/usr/bin/env python3
"""
End-to-end demonstration of the boot-attestation chain.

Run:  python3 demo.py

Every scenario works on a throwaway copy of the stage images, so the repository
is never left in a tampered state and the demo produces identical output on a
second run.

Scenarios
  1  clean boot                  -> TRUSTED, key released
  2  tampered kernel             -> UNTRUSTED, kernel named, key withheld
  3  replayed quote              -> UNTRUSTED, stale nonce
  4  forged signature            -> UNTRUSTED, wrong attestation key
  5  substituted event log       -> UNTRUSTED, log disagrees with signed quote
  6  malformed input             -> UNTRUSTED, fails closed without crashing
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path

from attestation import (
    BootChain,
    MockTPM,
    Quote,
    Verifier,
    build_policy_from_clean_boot,
)
from attestation.boot_chain import ATTESTED_PCRS, BOOT_STAGES, CHAIN_PCR
from make_images import write_clean_images

HERE = Path(__file__).parent
W = 74


# --- presentation helpers ---------------------------------------------------


def header(title: str) -> None:
    print("\n" + "=" * W)
    print(title)
    print("=" * W)


def field(label: str, value: str) -> None:
    print(f"  {label:<22} {value}")


def verdict(result) -> None:
    mark = "TRUSTED" if result.trusted else "UNTRUSTED"
    print()
    field("verdict", mark)
    if result.failing_stage:
        field("failing stage", result.failing_stage)
    field("reason", result.reason)
    for key, value in result.detail.items():
        shown = value if len(str(value)) <= 40 else f"{str(value)[:37]}..."
        field(f"  {key}", str(shown))
    field(
        "key release",
        result.released_key if result.released_key else "WITHHELD",
    )


def attest(node_tpm, verifier, label="attestation") -> object:
    """Run one full challenge-response exchange against the verifier."""
    nonce = verifier.issue_challenge()
    quote = node_tpm.quote(nonce, indices=ATTESTED_PCRS)
    log = node_tpm.event_log()
    return verifier.verify(quote, log), quote, log


# --- scenarios --------------------------------------------------------------


def scenario_clean(workdir: Path, verifier_factory) -> bool:
    header("SCENARIO 1 — Clean boot")
    tpm = MockTPM()
    chain = BootChain(tpm, workdir)
    chain.boot()

    verifier = verifier_factory(tpm)
    print("  Boot chain measured, in order (each stage before it ran):")
    logged = {(e.stage, e.pcr_index): e for e in tpm.event_log()}
    print(f"    {'stage':<12} {'reg':<5} {'measurement':<22} {'chain value':<22}")
    for stage, pcr_index in BOOT_STAGES:
        own = logged[(stage, pcr_index)]
        chained = logged[(stage, CHAIN_PCR)]
        print(
            f"    {stage:<12} PCR{pcr_index}  {own.measurement[:20]}.. "
            f"{chained.pcr_after[:20]}.."
        )

    result, _, _ = attest(tpm, verifier)
    verdict(result)
    return result.trusted and result.released_key is not None


def scenario_tampered_kernel(workdir: Path, verifier_factory) -> bool:
    header("SCENARIO 2 — Tampered kernel image")

    kernel = workdir / "kernel.img"
    original = kernel.read_text()
    # A single added line: the smallest change that still alters the digest.
    kernel.write_text(original + "backdoor: reverse_shell 10.0.0.6:4444\n")
    print("  Modified kernel.img (one line appended)")

    tpm = MockTPM()
    chain = BootChain(tpm, workdir)
    chain.boot()

    verifier = verifier_factory(tpm)
    result, _, _ = attest(tpm, verifier)

    print("\n  Stage register (attribution)   vs   chain register (propagation):")
    print(f"    {'stage':<12} {'own PCR':<10} {'chain PCR':<10}")
    logged = {(e.stage, e.pcr_index): e for e in tpm.event_log()}
    for s in verifier.policy.stages:
        own = logged.get((s.stage, s.pcr_index))
        chained = logged.get((s.stage, CHAIN_PCR))
        own_flag = "match" if own and own.pcr_after == s.pcr_after else "DIVERGE"
        chain_flag = "match" if chained and chained.pcr_after == s.chain_after else "DIVERGE"
        print(f"    {s.stage:<12} {own_flag:<10} {chain_flag:<10}")
    print("\n    Only PCR2 diverges on its own register — that is the attribution.")
    print("    The chain register diverges from the kernel onward and never")
    print("    recovers: no later extend can undo an earlier measurement.")

    verdict(result)

    kernel.write_text(original)  # restore for later scenarios
    return (
        not result.trusted
        and result.failing_stage == "kernel"
        and result.released_key is None
    )


def scenario_replay(workdir: Path, verifier_factory) -> bool:
    header("SCENARIO 3 — Replayed quote (captured from an earlier clean boot)")

    tpm = MockTPM()
    chain = BootChain(tpm, workdir)
    chain.boot()
    verifier = verifier_factory(tpm)

    first, captured_quote, captured_log = attest(tpm, verifier)
    print(f"  Attacker captures a quote that legitimately passed: {first.trusted}")
    print(f"  Captured nonce: {captured_quote.nonce[:24]}...")

    # The verifier issues a NEW challenge; the attacker resends the old quote.
    fresh_nonce = verifier.issue_challenge()
    print(f"  Verifier issues a fresh challenge:  {fresh_nonce[:24]}...")
    print("  Attacker replays the captured quote unchanged")

    result = verifier.verify(captured_quote, captured_log)
    verdict(result)
    return not result.trusted and result.released_key is None


def scenario_forged_signature(workdir: Path, verifier_factory) -> bool:
    header("SCENARIO 4 — Forged quote signed with an attacker's key")

    tpm = MockTPM()
    chain = BootChain(tpm, workdir)
    chain.boot()
    verifier = verifier_factory(tpm)

    # The attacker owns a TPM-like object but not the AK the verifier trusts.
    rogue = MockTPM()
    nonce = verifier.issue_challenge()
    # Forge PCR values that look exactly like a clean boot.
    clean_pcrs = tpm.pcr_values(ATTESTED_PCRS)
    forged = rogue.quote(nonce, indices=ATTESTED_PCRS)
    forged = Quote(
        pcr_values=clean_pcrs,
        nonce=nonce,
        signature=rogue.quote(nonce, indices=ATTESTED_PCRS).signature,
        algorithm=forged.algorithm,
    )
    print("  Attacker presents correct PCR values and a fresh nonce,")
    print("  but signs with a key the verifier does not trust.")

    result = verifier.verify(forged, tpm.event_log())
    verdict(result)
    return not result.trusted and result.released_key is None


def scenario_substituted_log(workdir: Path, verifier_factory) -> bool:
    header("SCENARIO 5 — Tampered boot with a substituted (clean-looking) log")

    # Capture what a clean log looks like.
    clean_tpm = MockTPM()
    BootChain(clean_tpm, workdir).boot()
    clean_log = clean_tpm.event_log()

    # Now boot tampered code on the real node.
    kernel = workdir / "kernel.img"
    original = kernel.read_text()
    kernel.write_text(original + "rootkit: loaded\n")

    tpm = MockTPM()
    BootChain(tpm, workdir).boot()
    verifier = verifier_factory(tpm)

    nonce = verifier.issue_challenge()
    real_quote = tpm.quote(nonce, indices=ATTESTED_PCRS)
    print("  Node boots tampered code, signs a truthful quote,")
    print("  then sends a pristine event log alongside it.")

    result = verifier.verify(real_quote, clean_log)
    verdict(result)

    kernel.write_text(original)
    return not result.trusted and result.released_key is None


def scenario_malformed(workdir: Path, verifier_factory) -> bool:
    header("SCENARIO 6 — Malformed and unexpected input (fail-closed check)")

    tpm = MockTPM()
    BootChain(tpm, workdir).boot()
    verifier = verifier_factory(tpm)

    bad_inputs = [
        ("quote is None", None, []),
        ("event log is None", {"pcr_values": {}, "nonce": "aa", "signature": "bb"}, None),
        ("empty event log", None, []),
        (
            "non-hex PCR value",
            {
                "pcr_values": {"0": "not-a-hex-digest"},
                "nonce": "ab" * 16,
                "signature": "cd" * 64,
            },
            [],
        ),
        (
            "truncated signature",
            {
                "pcr_values": {"0": "00" * 32},
                "nonce": "ab" * 16,
                "signature": "cd" * 8,
            },
            [{"pcr_index": 0, "stage": "firmware", "measurement": "11" * 32,
              "pcr_after": "22" * 32}],
        ),
        ("event log is a string", {"pcr_values": {"0": "00" * 32},
                                   "nonce": "ab" * 16,
                                   "signature": "cd" * 64}, "not-a-list"),
    ]

    all_rejected = True
    for label, quote, log in bad_inputs:
        try:
            result = verifier.verify(quote, log)
            status = "TRUSTED (BUG!)" if result.trusted else "rejected"
            if result.trusted:
                all_rejected = False
            print(f"  {label:<26} -> {status}: {result.reason[:44]}")
        except Exception as exc:  # noqa: BLE001 - the whole point is that this shouldn't happen
            all_rejected = False
            print(f"  {label:<26} -> CRASHED ({type(exc).__name__}: {exc})")

    print("\n  Verifier must reject every one of these without raising.")
    return all_rejected


# --- runner -----------------------------------------------------------------


def main() -> int:
    print("=" * W)
    print("SECURE BOOT / REMOTE ATTESTATION — CONCEPT DEMO")
    print("=" * W)

    # Always start from pristine images so a second run behaves identically.
    write_clean_images()

    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp) / "images"
        shutil.copytree(HERE / "images", workdir)

        policy = build_policy_from_clean_boot(workdir)
        policy.save(HERE / "policy" / "golden_values.json")
        print("\nGolden-value policy derived from a known-good boot:")
        print(f"  {'stage':<12} {'own PCR':<26} {'chain PCR' + str(CHAIN_PCR):<26}")
        for stage in policy.stages:
            print(
                f"  {stage.stage:<12} PCR{stage.pcr_index} {stage.pcr_after[:20]}.. "
                f"     {stage.chain_after[:20]}.."
            )

        def verifier_factory(node_tpm):
            # The verifier trusts this node's AK public half; everything else
            # about the node is unverified until a quote proves otherwise.
            return Verifier(policy, node_tpm.ak_public_key())

        scenarios = [
            scenario_clean,
            scenario_tampered_kernel,
            scenario_replay,
            scenario_forged_signature,
            scenario_substituted_log,
            scenario_malformed,
        ]

        results = [fn(workdir, verifier_factory) for fn in scenarios]

    header("SUMMARY")
    names = [
        "clean boot -> trusted, key released",
        "tampered kernel -> untrusted, kernel named",
        "replayed quote -> untrusted",
        "forged signature -> untrusted",
        "substituted log -> untrusted",
        "malformed input -> rejected, no crash",
    ]
    for name, ok in zip(names, results):
        print(f"  [{'PASS' if ok else 'FAIL'}]  {name}")

    passed = all(results)
    print("\n" + ("All scenarios behaved as designed." if passed else "SOME SCENARIOS FAILED."))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
