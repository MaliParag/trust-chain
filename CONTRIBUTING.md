# Contributing

Thank you for helping improve *The Platform Trust Chain Series*. Technical corrections, primary-source updates, and diagnostic refinements across the Windows, Apple, Linux, and Android volumes are welcome.

## Editorial Ground Rules

All volumes share the portable craft standards in [`editorial.md`](editorial.md), parameterized per volume via `books/<slug>/house.json`:

1. **Sustained book prose:** Write body sections in connected narrative paragraphs rather than bulleted slide outlines; house opening chapter coordinates inside structured `Overview` cards where configured.
2. **Primary-source citations:** Anchor non-trivial claims to numbered entries (`[N]`) in `books/<slug>/src/back-matter/70-references.md`, keeping verbatim quotations exact.
3. **Clean typography & zero leaks:** Keep prose, headings, tables, and SVG diagrams free of em-dashes (`U+2014`), emojis, inline paragraph/table boldface, and leaked repository paths.
4. **Architectural gap analysis:** Present offensive techniques strictly as boundary gap analysis isolating why an invariant failed and what closed it.

## Workflow

1. Edit the relevant volume under `books/<windows|apple|linux|android>/src/`.
2. Preview a single volume with `(cd books/<slug> && mdbook serve --open)`, or build the entire multi-volume site into `./book` with `npm run build`.
3. If chapter titles or reading order change in `books/<slug>/house.json`, run `npm run summary`.
4. Run `npm run audit` (`python3 tools/audit_book.py`) to verify all volumes pass editorial, citation, and link checks.
5. Open a pull request naming the primary specification or live OS build used to verify the change.

By contributing, you agree that your contributions are licensed under the project's [CC BY-NC-SA 4.0](LICENSE) terms, and grant Parag Mali a perpetual, worldwide, non-exclusive, royalty-free, irrevocable license to use, reproduce, adapt, publish, and distribute your contribution for any purpose, including commercial editions.
