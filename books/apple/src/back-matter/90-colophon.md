# Colophon

*The Apple Trust Chain* (Volume II of *The Platform Trust Chain Series*) shares the unified *Platform Trust Chain Monograph* typesetting across web and print editions, pairing `Georgia` long-form serif body prose with system sans-serif display headings, structured five-coordinate `Overview` cards, proportional `<colgroup>` tables, and `SF Mono` / `Menlo` code blocks.

**Production Pipeline.** The text is authored in CommonMark Markdown with `KaTeX` mathematical typesetting (`$...$` and `$$...$$`) and compiled into both a searchable responsive web edition and a `7.00 x 9.25 in` print-ready PDF edition (`the-apple-trust-chain.pdf`) via the shared multi-volume publishing toolchain (`mdBook`, `tools/mdbook-trustchain.mjs`, `tools/gen-summary.mjs`, `tools/build-pdf.mjs`, and `tools/audit_book.py`) governed by the craft principles in `editorial.md`.

**Vector Architecture Diagrams.** All sixty-four architectural figures in this volume are generated programmatically in Python via `books/apple/tools/gen_diagrams.py` atop `tools/diagram_lib.py`, enforcing strict orthogonal connector geometry, row-synchronized split domains, masked edge labels, and automated seven-way geometric collision verification on every build.

**License.** Copyright © 2026 Parag Mali. Licensed under [CC BY-NC-SA 4.0](https://creativecommons.org/licenses/by-nc-sa/4.0/), with all commercial rights reserved by the author. See [Copyright](../front-matter/01-copyright.md).
