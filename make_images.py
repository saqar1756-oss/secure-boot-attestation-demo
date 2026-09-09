#!/usr/bin/env python3
"""
Create the clean stage images used by the simulated boot chain.

Each file stands in for a real boot artefact (firmware blob, bootloader, kernel
image, OS root, AI runtime bundle).  Contents are fixed text, so the digests are
deterministic and the demo produces the same golden values on every machine.

Rerunning this script rewrites the images to their pristine state, which is how
the demo recovers after a tamper scenario.
"""

from pathlib import Path

IMAGE_DIR = Path(__file__).parent / "images"

STAGE_IMAGES = {
    "firmware": (
        "MOCK-FIRMWARE v1.4.2\n"
        "role: core root of trust for measurement\n"
        "measures: bootloader\n"
        "build: reproducible-2026-02-11\n"
    ),
    "bootloader": (
        "MOCK-BOOTLOADER v2.8.0\n"
        "role: load and measure the kernel image\n"
        "measures: kernel\n"
        "cmdline: ro quiet ima_policy=tcb\n"
    ),
    "kernel": (
        "MOCK-KERNEL 6.8.0-generic\n"
        "role: initialise hardware, mount root, measure the OS\n"
        "measures: os\n"
        "config: CONFIG_IMA=y CONFIG_TCG_TPM=y\n"
    ),
    "os": (
        "MOCK-OS base-image 24.04\n"
        "role: provide the runtime environment\n"
        "measures: ai_runtime\n"
        "packages: minimal, no interactive shell\n"
    ),
    "ai_runtime": (
        "MOCK-AI-RUNTIME v0.9.3\n"
        "role: inference service holding the protected workload\n"
        "model: mock-classifier-7b\n"
        "weights-sha: pinned-at-build\n"
    ),
}


def write_clean_images(image_dir: Path = IMAGE_DIR) -> Path:
    image_dir.mkdir(parents=True, exist_ok=True)
    for stage, content in STAGE_IMAGES.items():
        (image_dir / f"{stage}.img").write_text(content)
    return image_dir


if __name__ == "__main__":
    path = write_clean_images()
    print(f"Wrote {len(STAGE_IMAGES)} clean stage images to {path}")
