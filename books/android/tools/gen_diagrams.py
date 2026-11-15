#!/usr/bin/env python3
"""Diagram generator for The Android Trust Chain (Volume IV), backed by shared tools/diagram_lib.py."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
import diagram_lib  # noqa: F401

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))

def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    print("Verified diagram directory for android:", DIAG_DIR)

if __name__ == "__main__":
    main()
