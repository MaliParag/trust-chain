#!/usr/bin/env python3
"""Master diagram builder for The Windows Trust Chain.

Regenerates all 68 curated architectural SVG diagrams across Foundations and
Chapters 1-20 with automatic text-wrapping, pill-masked edge labels, zero
em-dashes, and strict mathematical collision verification, and prunes orphaned
unreferenced SVGs from src/diagrams/.
"""
import glob
import os
import re
from gen_diagrams_p1 import generate_part1
from gen_diagrams_p2 import generate_part2

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIAG_DIR = os.path.join(REPO, "src", "diagrams")


def collect_referenced_svgs() -> set:
    used = set()
    for p in glob.glob(os.path.join(REPO, "src", "**", "*.md"), recursive=True):
        if p.endswith(("16-secure-boot.old.md", "70-references.md", "SUMMARY.md")):
            continue
        txt = open(p, encoding="utf-8").read()
        for m in re.finditer(r"^!\[.+?\]\(diagrams/([^)]+)\)\s*$", txt, flags=re.M):
            used.add(m.group(1))
    return used


def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    generate_part1(DIAG_DIR)
    generate_part2(DIAG_DIR)

    used = collect_referenced_svgs()
    existing = {os.path.basename(p) for p in glob.glob(os.path.join(DIAG_DIR, "*.svg"))}
    missing = used - existing
    assert not missing, f"Missing referenced SVGs: {missing}"

    removed = 0
    for svg in sorted(existing - used):
        os.remove(os.path.join(DIAG_DIR, svg))
        removed += 1

    print(f"Verified all {len(used)} referenced diagrams in src/diagrams/ (removed {removed} unreferenced legacy SVGs).")


if __name__ == "__main__":
    main()
