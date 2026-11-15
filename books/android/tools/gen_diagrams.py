#!/usr/bin/env python3
"""Diagram generator for The Android Trust Chain (Volume IV), backed by shared tools/diagram_lib.py."""
import glob
import os
import sys

sys.dont_write_bytecode = True

TOOLS_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools"))
LOCAL_TOOLS = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, TOOLS_ROOT)
sys.path.insert(0, LOCAL_TOOLS)

import diagram_lib  # noqa: F401, E402
from gen_diagrams_p1 import generate_part1  # noqa: E402
from gen_diagrams_p2 import generate_part2  # noqa: E402

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    generate_part1(DIAG_DIR)
    generate_part2(DIAG_DIR)
    svgs = sorted(glob.glob(os.path.join(DIAG_DIR, "*.svg")))
    print(f"Generated and 7-way collision-verified {len(svgs)} SVG diagrams in {DIAG_DIR}")


if __name__ == "__main__":
    main()
