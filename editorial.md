# Editorial and Book-Craft Playbook

This document distills universal standards for authoring, editing, illustrating, and producing a rigorous technical book. Part I states portable principles of craft that apply to any technical monograph (systems, security, cryptography, compilers, distributed systems, algorithms, or AI) without forcing different books into identical surface templates. Part II records the specific house configuration chosen for *The Windows Trust Chain*.

---

## Part I · Universal Principles of Technical Book Craft

### 1. Book Architecture and Scope Ownership

* **Organize Around One Governing Spine, Not an Encyclopedia:** A great technical book advances one coherent argument from start to finish (for example: how trust is inherited across layers, how state scales under faults, or how reductions preserve hardness). Every chapter must earn its place by adding a distinct link, constraint, or abstraction to that spine.
* **Single Canonical Ownership (No Forward Pre-emption, No Backward Recaps):** Every concept, algorithm, protocol, or historical failure belongs to *one* canonical home chapter.
  * *Upstream:* Never spend pages previewing a downstream chapter's architecture, comparison tables, or case studies; hand off the open problem in one or two sentences and cross-reference forward.
  * *Downstream:* When Chapter $N$ builds on a limitation established in Chapter $N-1$, state the inherited premise in a single sentence, link back, and proceed immediately to the new mechanism without re-narrating the history or failure stories.
* **Synthesize Consolidations Around Shared Abstractions:** When merging overlapping drafts or closely coupled subtopics into one chapter, rewrite around their shared underlying model rather than concatenating separate mini-chapters end to end.
* **Prioritize Deployed Reality Over Ghost Curiosities:** Dedicate the main narrative to constructions, protocols, and architectures that actually run in practice (or provably govern real systems). Confine unshipped proposals, abandoned standards, or speculative drafts to brief design-space contrasts explaining *why* practice chose a different trade-off.
* **Direct-Ancestor History Only:** Include historical context only when it explains why a current design carries a specific constraint or interface today. Establish the legacy limitation in one or two sharp paragraphs, then move directly to the modern mechanism.
* **Discipline the Scope Perimeter:** Exclude adjacent ecosystems, hardware subsystems, or policy debates unless understanding a core design decision in *this* book's subject is impossible without them.

---

### 2. Chapter Rhythm Without Cookie-Cutter Templates

A book should feel cohesive across its own chapters without looking stamped from the same mold as every other book. Separate the *functional arc* a reader needs from the *surface headings* a specific subject calls for:

* **Preserve a Clear Intellectual Arc:** Strong technical chapters guide the reader through a natural progression:
  1. *Orient:* Establish where the chapter sits in the larger argument and what core question or invariant it owns.
  2. *Motivate:* Frame the concrete engineering problem, workload constraint, or threat model before naming solutions.
  3. *Construct:* Walk through the mechanism, data structures, equations, or protocol flows at full fidelity.
  4. *Stress-Test:* Examine where the design breaks, degrades, or fails in the real world (failure modes, attacks, edge cases, or bottlenecks).
  5. *Bound:* Isolate fundamental theoretical limits, impossibility results, and permanent trade-offs.
  6. *Verify or Apply (When Relevant):* Show concisely how to observe, test, or reproduce the behavior in practice.
  7. *Connect:* Close with what has been established and what remains open for the next chapter.
* **Adapt Section Shapes to the Book's Genre:** Never copy another book's literal `H2` headings or summary tables blindly across genres.
  * A *systems security* book naturally pairs an architectural deep dive with an attack gap analysis and live host verification.
  * A *cryptography or formal methods* book naturally pairs formal game definitions and constructions with security reductions and implementation pitfalls.
  * A *distributed systems or database* book naturally pairs storage/network mechanics with fault-injection scenarios, consistency anomalies, and latency/throughput trade-offs.
  * An *algorithms or compilers* book naturally pairs problem formulation and invariants with worked transformations, complexity bounds, and pathological inputs.
* **Enforce Causal Ordering:** Never introduce a mitigation, optimization, or refinement before introducing the failure mode, bottleneck, or attack that forced its creation.
* **Quarantine Hands-On Mechanics from Conceptual Flow:** When a book includes terminal diagnostics, benchmark harnesses, or implementation exercises, place them in a dedicated section (or clearly bounded lab block) rather than breaking up architectural derivations mid-argument. Keep interactive commands short (`1-4` lines) so readers can run and read them at a glance rather than paging through boilerplate scripts.

---

### 3. Prose Cadence and Voice

* **Write in Sustained Paragraphs, Not Slide Outlines:** Published books live in connected paragraphs (`>= 75%` of non-table text), not bullet lists.
  * Do not string together `60-120`-word `* **Bold Heading:**` pseudo-paragraphs across body sections, and do not write narrative primers as strings of `**Term.**` dictionary blurbs (reserve alphabetical definitions for a Glossary).
  * Even multi-step protocols, compilation passes, and verification gates usually read with greater clarity and authority when woven into cohesive paragraphs connected by explicit causal transitions (*"First, ..."*, *"Once the digest is computed, ..."*, *"Only after surviving both checks..."*).
  * If chapters open with structured coordinates or metadata, house them in a purpose-built visual container (such as an outlined specification card or epigraph box) rather than raw bullet points, so the transition into continuous book prose is unmistakable.
* **Open Directly in Technical Reality (No Fictional Vignettes):** Never open chapters or sections with invented characters, dramatized timestamps (*"It is 3:14 a.m. in a SOC..."*), or fictional war stories. Open immediately with the concrete technical tension or a documented, cited real-world event.
* **Peer-to-Peer Authority (Zero Meta-Commentary):** Treat the reader as an experienced peer.
  * *No structural narration:* Never write *"This is the chapter's densest section"*, *"The conclusion is the part most engineers skip"*, or *"We have walked the chain; next we ask..."*.
  * *No performative honesty or apologies:* Never boast that the text is telling the truth or apologize for lab constraints (*"This example is deliberately modest"*). State what an interface, proof, or measurement shows and stop.
  * *No rhetorical gimmicks or persona splits:* Avoid `Aha #1` labels, helpdesk hand-holding (*"Open a terminal window and type..."*), and fragmented endings addressed to role-play personas (*"For an executive... For a developer... For a researcher..."*).
* **Make Every Callout Box Earn Its Border (No Echo Chambers):** Reserve callout blocks (`Key idea`, `Definition`, `Warning`, `Theorem`) strictly for load-bearing invariants, formal definitions, or subtle traps. Never use a callout to repeat, preview, or summarize a claim already stated in the adjacent paragraph, and never use callouts as editorial sticky notes (`Recap: owned by Chapter 4`).
* **Canonical Case-Study Placement (No Name-Dropping Fatigue):** Do not drop the name of a famous failure, bug, or theorem ten times across opening sections before explaining it. Mention it briefly with a cross-reference where needed, and analyze it thoroughly once in its canonical section.

---

### 4. Typographic and Surface Hygiene

* **Typographic Restraint:** Let sentence structure and verb choice carry emphasis instead of typographic shouting.
  * Avoid boldface (`**...**`) inside body paragraphs and table cells.
  * Use monospace backticks (`` `identifier` ``) for code symbols, types, registers, wire messages, paths, and status codes.
  * Reserve *italics* sparingly for genuine one- or two-word semantic contrast or first-use conceptual terms.
  * Reserve boldface strictly for structural chrome (callout lead-ins, specification-card keys, or standalone glossary headwords).
* **Clean Punctuation and Mathematical Notation:** Prefer crisp clauses, colons, semicolons, and parentheses over habitual em-dash chains or raw ASCII arrows (`->`) in prose. Typeset mathematical expressions, state transitions, and complexity or probability bounds cleanly in TeX math (`$...$` / `$$...$$`) with every variable defined in context.
* **Zero Authoring or Pipeline Leaks:** Published prose must never leak repository file paths (`diagrams/foo.svg`, `src/ch04.md`), internal editorial rule numbers (`Law 16`), scraper/crawler artifacts (`HTTP 403`), provenance scaffolding, or internal build jargon (`manuscript`, `TODO`).
* **Hyperlinked, Verified Cross-References:** Every cross-reference to another chapter, section, figure, glossary term, or bibliography entry should be a working link whose visible number or title matches the canonical table of contents.

---

### 5. Rigor, Evidence, and Attribution

* **Separate Mechanism Validity from System-Level Meaning:** Always distinguish what a primitive guarantees locally from what a larger system assumes globally:
  * In *security*: cryptographic signature or hash validity (*"signed by key $K$"*) is never automatically authorization or safety (*"key $K$ is permitted to act on resource $R$"*).
  * In *distributed systems*: protocol liveness or consensus under a fault model is never identical to end-to-end application correctness across unmodeled network or storage faults.
  * In *algorithms and ML*: asymptotic or benchmark performance under i.i.d. assumptions is never identical to worst-case adversarial or cache/memory-hierarchy behavior.
* **Primary-Source Citations Only:** Ground non-trivial claims in primary specifications, standards (`RFC`, `ISO`, `NIST`, `IEEE`, `W3C`), vendor architecture references, peer-reviewed papers, or official incident reports.
* **Curated, Orphan-Free Bibliography:** Maintain sequential citation numbering, strip internal research notes from reference entries, verify well-formed URLs/DOIs, and prune uncited bibliography orphans on every build. Preserve verbatim quotations and their original punctuation exactly.

---

### 6. Visual Architecture: Diagrams, Tables, Covers, and Print/PDF

* **Every Diagram Must Teach Structure Prose Cannot:** Include a diagram only when spatial partitioning, multi-actor protocol timing, state lattices, or multi-dimensional trade-off spaces become clearer visually than in prose. Never add decorative boxes that merely echo a simple linear paragraph, and keep every figure caption synchronized with the exact rows, columns, and labels shown in the current graphic.
* **Strict Orthogonal Geometry and Zero Visual Collisions:**
  * Route connectors strictly horizontally and vertically unless radial geometry requires otherwise.
  * When a spanning summary layer connects to multiple columns above or below it, align outer widths and drop straight vertical arrows down each column's exact center rather than funneling through crooked doglegs or stepped T-junctions.
  * In side-by-side domain diagrams, synchronize paired row heights so cross-boundary bridges run strictly horizontally.
  * Mask edge labels inside opaque background pills with explicit clearance (`>= 3 px`) from arrowheads and box borders, and mechanically verify every diagram against text-on-text, line-through-text, pill-on-arrowhead, card-on-card, and parallel double-track overlaps.
* **Proportional, Overflow-Free Tables:** Wide multi-column tables break both web layouts (via hidden horizontal clipping) and print/PDF engines (by triggering global shrink-to-fit downscaling across the entire book). Always combine `table-layout: fixed` and `width: 100%` with content-weighted `<colgroup>` column percentages and clean line-break opportunities (`<wbr>`) at path and identifier separators (`\`, `/`, `_`).
* **Cohesive Covers and Print Pagination:**
  * Design front and back covers around an architectural visual metaphor native to the book's thesis rather than stock clichés, keeping uppercase letter-spacing moderate (`<= 1.5 px`) so PDF text selection never splits words.
  * Match PDF page trim (`7 x 9.25 in`, `6 x 9 in`, or `Letter`) to the cover's exact aspect ratio, render front and back covers on full-bleed `margin: 0` named pages with running headers/footers suppressed, prevent page splits inside callouts, figures, and table rows (`break-inside: avoid`), and generate native PDF bookmark outlines.

---

### 7. Mechanical Verification ("Enforce What You Care About")

Human review catches nuance, voice, and argument structure; deterministic scripts catch drift across hundreds of pages. Every book repository should maintain a single automated audit (`tools/audit_book.py` or equivalent) run before merging that verifies:

1. Expected chapter structure and heading sequence per the book's house sheet.
2. Prose-vs-list cadence and typographic restraint (no disallowed inline/table bolding, banned punctuation, or authoring/path leaks).
3. Reference integrity (`100%` of inline `[N]` citations resolve; `0` uncited bibliography orphans).
4. Cross-reference parity (every visible `Chapter K` link resolves to the actual `K`-th chapter in the table of contents, and all HTML `#anchor` fragments resolve).
5. Diagram collision/orthogonality invariants and zero horizontal DOM overflow across all tables, code blocks, and figures in the print/PDF render.

---

## Part II · House Sheet for *The Windows Trust Chain*

*(When adapting Part I to a new book, replace only this section with that book's domain-specific structure, conventions, and chapter map.)*

* **Core Thesis:** Every security guarantee in modern Windows is inherited upward from immutable silicon roots (`Boot Guard`, `UEFI`, `TPM 2.0`, `Pluton`) through hypervisor `SLAT` isolation (`VTL0`/`VTL1`), kernel code integrity, local tokens and data vaults, Active Directory and passkey protocols, `ETW` telemetry, and cloud `Zero Trust` / `Confidential VM` enforcement; the chain snaps whenever a higher layer mistakes cryptographic validity for delegated authorization.
* **Target Audience:** Systems security architects, principal detection engineers, incident responders, and OS/cloud platform engineers.
* **Chapter Progression (7 `H2` Sections):**
  1. `Overview` (rendered as a colored, outlined 5-coordinate specification card: `Role in the Chain`, `Core Security Invariant`, `Trusted Computing Base (TCB)`, `Primary Failure Modes`, `Handoff`)
  2. `Core Engineering Problem & Threat Model`
  3. `Architectural Deep Dive`
  4. `Attack Catalog & Gap Analysis` (opening with the standardized 6-column table: `Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path`, treating attacks strictly as architectural gap analysis rather than exploit tutorials)
  5. `Theoretical Limits & Structural Invariants`
  6. `Inspecting and Verifying on a Running System` (read-only `1-4` line PowerShell, Win32, WMI/CIM, and cloud CLI queries)
  7. `Summary & Handoff`
* **House Typographic Choices:** Zero em-dashes (`U+2014`) and zero emojis in prose, tables, headings, diagrams, and commit messages; `0` bulleted or numbered lists outside the `Overview` card, `70-references.md`, and `95-index.md`; `Figure: ` caption prefix on all 76 vector SVG diagrams; `7.00 x 9.25 in` PDF trim (`tools/build-pdf.mjs`).
* **23-Chapter Canonical Map:**
  * *Opening:* `Prologue` · `Foundations`
  * *Part I · Silicon (Ch. 1-5):* `1. Secure Boot` · `2. The TPM` · `3. Pluton` · `4. Measured Boot` · `5. Attestation`
  * *Part II · Kernel & Code (Ch. 6-9):* `6. The Secure Kernel and VBS` · `7. Code Integrity and Application Control` · `8. Protected Process Light` · `9. Process Mitigation Policies`
  * *Part III · Credentials & Access (Ch. 10-17):* `10. Windows Access Control, Integrity Levels, and Impersonation` · `11. Data Protection and Local Secret Custody` · `12. Credential Guard and LSASS Isolation` · `13. The Death of NTLM` · `14. Kerberos and Ticket Forgery` · `15. Enterprise PKI, Service Identities, and Hybrid Bridges` · `16. Pass-the-Hash to Pass-the-PRT` · `17. Windows Hello and Passkeys`
  * *Interlude · Watching the Chain (Ch. 18):* `18. ETW: The EDR Substrate`
  * *Part IV · Cloud (Ch. 19-22):* `19. Zero Trust` · `20. Continuous Access Evaluation` · `21. Workload and AI Agent Security` · `22. Confidential VMs`
  * *Finale · When the Chain Snaps (Ch. 23):* `23. When the Chain Snaps: Storm-0558`
