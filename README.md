# Secure Boot / Remote Attestation — Concept Demo

![tests](https://github.com/saqar1756-oss/secure-boot-attestation-demo/actions/workflows/tests.yml/badge.svg)

A simulated boot-attestation chain: a mock TPM with correct PCR extend
semantics, a five-stage measured boot chain, and a remote verifier that
releases a key only when a signed quote matches a golden-value policy.

No hardware TPM required. Pure Python, one runtime dependency.

---

## Verify this in two minutes

```bash
git clone https://github.com/saqar1756-oss/secure-boot-attestation-demo.git
cd REPO
pip install -r requirements.txt

python3 demo.py          # all six scenarios, exits 0 only if all behave correctly
python3 demo.py          # run it again — output is identical apart from nonces
python3 -m pytest -q     # 58 tests
```

Nothing else is needed: no configuration, no services, no network access, and
no fixture files to generate by hand. `demo.py` creates its own stage images,
derives the golden-value policy from a known-good boot, and works on a
temporary copy so the repository is never left in a tampered state.

**Expected result:** every scenario reports `PASS` and the process exits `0`.

---

## Quick start (development)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

python3 demo.py          # run all six scenarios
python3 -m pytest -q     # run the test suite
```

Tested on Python 3.10, 3.11 and 3.12.

---

## What the demo shows

| # | Scenario | Expected verdict |
|---|----------|------------------|
| 1 | Clean boot | **TRUSTED** — key released |
| 2 | Kernel image tampered | **UNTRUSTED** — `kernel` named, key withheld |
| 3 | Quote captured and replayed | **UNTRUSTED** — stale nonce |
| 4 | Quote forged with attacker's key | **UNTRUSTED** — signature invalid |
| 5 | Tampered boot + substituted clean log | **UNTRUSTED** — log contradicts quote |
| 6 | Malformed / unexpected input | Rejected, no crash |

---

## Architecture

```
                    ┌─────────────────────────────────────────┐
                    │  NODE                                   │
                    │                                         │
   firmware ────────┤  measure ─► extend(PCR0) ─► execute     │
      │             │                    │                    │
   bootloader ──────┤  measure ─► extend(PCR1) ─► execute     │
      │             │                    │                    │
   kernel ──────────┤  measure ─► extend(PCR2) ─► execute     │
      │             │                    │                    │
   os ──────────────┤  measure ─► extend(PCR3) ─► execute     │
      │             │                    │                    │
   ai_runtime ──────┤  measure ─► extend(PCR4) ─► execute     │
                    │                    │                    │
                    │        every stage ALSO extends PCR7    │
                    │                    ▼                    │
                    │            ┌──────────────┐             │
                    │            │   MOCK TPM   │             │
                    │            │  PCR0..PCR7  │             │
                    │            │  AK keypair  │             │
                    │            └──────┬───────┘             │
                    └───────────────────┼─────────────────────┘
                                        │
                     quote = Sign_AK(PCRs ‖ nonce)
                     + event log (unsigned)
                                        │
                                        ▼
                    ┌─────────────────────────────────────────┐
                    │  REMOTE VERIFIER                        │
                    │  1. structure valid?                    │
                    │  2. nonce fresh and ours?               │
                    │  3. signature valid under AK?           │
                    │  4. log replays to the SIGNED PCRs?     │
                    │  5. values match golden policy?         │
                    │     ──► TRUSTED   → release key         │
                    │     ──► UNTRUSTED → name failing stage  │
                    └─────────────────────────────────────────┘
```

### Files

| Path | Role |
|------|------|
| `attestation/mock_tpm.py` | PCR bank, extend semantics, AK, quote |
| `attestation/boot_chain.py` | Five-stage measure-then-execute chain |
| `attestation/policy.py` | Golden-value policy: build, save, load |
| `attestation/verifier.py` | Challenge issuing and the five verification checks |
| `make_images.py` | Writes the clean stage images |
| `demo.py` | Runs all six scenarios end to end |
| `tests/test_attestation.py` | 58 tests |

---

## Design decisions worth explaining

### Why two registers per stage

Each stage extends **its own PCR** and a **shared chain register (PCR7)**.

Per-stage registers give *attribution*: if PCR2 diverges, the kernel is the
stage at fault. But per-stage registers are independent — a kernel tamper
leaves PCR3 and PCR4 looking perfectly normal, so per-stage registers alone
cannot show that a compromise taints everything after it.

The shared register gives *propagation*. Because
`PCR_new = H(PCR_old ‖ measurement)`, changing any one stage changes PCR7 from
that point forward, and no later extend can steer it back to the expected
value. This mirrors real TPM practice, where PCR7 aggregates secure-boot state.

The demo prints both columns side by side so the difference is visible.

### Why the event log is checked against the quote

The event log arrives **unsigned**. A compromised node could boot tampered code
and then send a pristine log. Step 4 of verification recomputes PCR values from
the log and requires the result to equal the values inside the *signed* quote.
The log is believed only because it agrees with something the TPM signed.
Scenario 5 demonstrates the attack this blocks.

### Why the nonce is single-use

The verifier generates a random 32-byte nonce, and the TPM signs it as part of
the quote payload. The nonce is consumed on first presentation regardless of
verdict, so a captured quote cannot be replayed against a later challenge
(scenario 3). Reusing a nonce would be exactly the kind of error that makes an
otherwise correct protocol worthless.

### Canonical signing payload

Both signer and verifier build the signed bytes identically:

```
b"MOCKTPM-QUOTE-v1" | algorithm | "0:<hex>,1:<hex>,..." | nonce_hex
```

PCR indices are sorted so dict ordering cannot change the signature, fields are
separated by a byte that cannot appear inside hex, and the version tag provides
domain separation so a signature over some other structure cannot be
reinterpreted as a quote.

---

## Mapping to real-world components

| This simulation | Real world |
|-----------------|------------|
| `MockTPM` | TPM 2.0 discrete chip or firmware TPM |
| Ed25519 AK keypair | TPM Endorsement Key → Attestation Key hierarchy |
| `extend()` | `TPM2_PCR_Extend` |
| `quote()` | `TPM2_Quote` |
| Stage image hashing | UEFI CRTM measurements + Linux IMA |
| Measure-then-execute chain | UEFI Secure Boot + TPM Measured Boot |
| `Verifier` | Remote attestation service (TCG RATS relying party) |
| `policy/golden_values.json` | Reference Integrity Manifest (RIM) |
| Nonce challenge | Anti-replay nonce in the TPM2_Quote protocol |

Note that UEFI Secure Boot and TPM Measured Boot are complementary, not
alternatives. Secure Boot refuses to *execute* unsigned code locally; measured
boot records what ran and lets a *remote* party judge it. This project
implements the second, and gates a key release on the verdict.

---

## What this simulation does not prove

- **No hardware root of trust.** The mock TPM is an ordinary object in the same
  process as its caller. Anything with code execution on the host could patch
  its state directly. A real TPM's guarantees come from being separate silicon,
  and nothing here reproduces that.
- **No key confidentiality.** A real TPM never lets the AK private key leave the
  chip. Here it is ordinary process memory.
- **No physical or side-channel resistance.** Entirely out of scope.
- **No real binary execution.** Stages are text files standing in for firmware,
  bootloader and kernel images; `_execute()` deliberately does nothing. The
  simulation is about what gets measured and in what order, not about emulating
  firmware.
- **The firmware self-measurement is assumed.** Trust bottoms out at the first
  stage, which nothing earlier measures. In hardware that is an immutable boot
  ROM; here it is an assumption the simulation cannot justify from inside
  itself.

The protocol logic is demonstrably correct. That is a different claim from any
particular machine being trustworthy, and only hardware closes the gap.

---

## Future work

- Replace the mock signing primitive with a real TPM 2.0 command interface via
  `swtpm`, keeping the protocol above it unchanged.
- A policy update and revocation path, so legitimate patches do not require
  weakening enforcement.
- Signed measurement allowlists instead of a static golden-value file.
