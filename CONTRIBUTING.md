# Contributing

Thank you for helping improve *The Windows Trust Chain*. Technical corrections,
primary-source updates, and diagnostic refinements are welcome.

## Ways to Help

- **Fix technical inaccuracies:** Data-structure details, protocol fields, build
  behavior changes, broken reference URLs, or typos.
- **Refine live diagnostics:** Keep PowerShell, Win32, WMI/CIM, and cloud CLI
  verification queries concise, read-only, and accurate on current Windows 11
  and Windows Server releases.
- **Improve the web edition:** mdBook styling, SVG diagram legibility,
  accessibility, or build scripts.

## Editorial and Structural Ground Rules

Every chapter adheres to the standards codified in [`editorial.md`](editorial.md):

1. **Predictable chapter progression:** Each numbered chapter follows the same
   seven `H2` sections: `Overview` (five standardized coordinates), `Core
   Engineering Problem & Threat Model`, `Architectural Deep Dive`, `Attack
   Catalog & Gap Analysis` (including the six-column summary table), `Theoretical
   Limits & Structural Invariants`, `Inspecting and Verifying on a Running
   System`, and `Summary & Handoff`.
2. **Diagnostics stay in Section 6:** All PowerShell/CLI inspection blocks live
   inside `Inspecting and Verifying on a Running System` and stay concise (1 to
   4 lines per command block).
3. **No exploit tutorials:** Offensive techniques appear strictly as architectural
   gap analysis isolating why a boundary failed and what closed it.
4. **Primary-source citations:** Anchor claims to numbered entries (`[N]`) in
   `src/back-matter/70-references.md`, keeping verbatim quotations exact.
5. **Clean typography:** Keep all prose, tables, and headings free of em-dashes
   (`U+2014`) and emojis.

## Making a Change

1. Edit the relevant Markdown source under `src/`.
2. Preview locally with `mdbook serve --open` or build `./book` via `mdbook build`.
3. If chapter titles or reading order change, run `node tools/gen-summary.mjs` to
   update `src/SUMMARY.md`.
4. Open a pull request describing the change and the primary source or live
   Windows build used to verify it.

By contributing, you agree that your contributions are licensed under the
project's [CC BY-NC-SA 4.0](LICENSE) terms. In addition, you grant Parag Mali a
perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use,
reproduce, adapt, publish, and distribute your contribution for any purpose,
including commercial editions of this book.
