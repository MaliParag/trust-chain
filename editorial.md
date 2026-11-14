# The Windows Trust Chain: Editorial and Writing Standards

This document defines the architectural, structural, and editorial standards for *The Windows Trust Chain*. Every chapter in the book must adhere to these principles to maintain a consistent, authoritative, and world-class engineering standard.

---

## 1. Chapter Structure and Opening Standard

Every chapter follows a strict, predictable structural progression:

1. **Chapter Title (`# Title`)**
2. **Overview (`## Overview`)**: A standardized 5-bullet block that replaces custom markup:
   * **Role in the Chain:** Where this subsystem sits in the stack and what lower links it builds on.
   * **Core Security Invariant:** The formal, precise security guarantee this link provides to higher layers.
   * **Trusted Computing Base (TCB):** The exact firmware, hardware, or software components that must remain uncompromised for this guarantee to hold.
   * **Primary Failure Modes:** How this boundary has historically been bypassed or undermined in practice.
   * **Handoff:** The unaddressed risks and responsibilities passed forward to subsequent chapters.
3. **Core Engineering Problem & Threat Model**: Opening immediately with the concrete technical problem and architectural limitations of predecessor mechanisms.
4. **Architectural Deep Dive**: Mechanism-level breakdown of the subsystem, data structures, and verification flows.
5. **Attack Catalog & Gap Analysis**: Structured summary table of real-world historical bypasses followed by focused gap-analysis case studies.
6. **Theoretical Limits & Structural Invariants**: Fundamental boundaries, trade-offs, and ecosystem dynamics.
7. **Inspecting and Verifying on a Running System**: Unified section of diagnostic commands, scripts, and hardening practices.
8. **Summary & Handoff**: Crisp verdict on what the link achieves and a transition to the next chapter.

---

## 2. Voice, Tone, and Style

### Direct Technical Grounding (No Fictional Storytelling)
* **Rule:** Do not open chapters with dramatized or fictional vignettes (for example: *"Picture a small business owner in December 2010..."* or *"The 3:14 a.m. Mimikatz that returned an empty hash..."*).
* **Instead:** Ground the chapter immediately in the technical reality and engineering threat model (for example: contrasting unauthenticated legacy BIOS sector-zero jumps with modern cryptographic firmware enforcement).

### Eliminate Self-Conscious Meta-Commentary
* **Rule:** Never narrate the chapter's own structure or lecture the reader about what other engineers supposedly miss.
* **Prohibited patterns:**
  * *"The conclusion is the part most engineers skip."*
  * *"The technical content of this section is not the hard part. The social and operational content... is the rest of the chapter."*
  * *"This is the chapter's mechanism-densest section, and the place a few key terms have to be exactly right."*
  * *"We have walked the chain end to end. The next question is..."*
  * *"This is the part you do today, on whatever Windows machine is in front of you."*
* **Instead:** State the technical reality plainly. Write with quiet, unforced authority.

### Eliminate Performative Honesty and Apologetic Posturing
* **Rule:** Never boast about the book's truthfulness or apologize for lab limitations.
* **Prohibited patterns:**
  * *"When the chapter shows you a blue block, it is telling you the truth about its own limits. That is deliberate."*
  * *"The captured block below is therefore deliberately modest."*
* **Instead:** State what an API, command, or register reports directly. Document empirical facts without moralizing.

### Prune Historical Overhang
* **Rule:** Do not spend extensive prose on distant pre-history that predates modern Windows architecture (e.g. detailed retrospectives on 1980s DOS floppy-disk viruses).
* **Instead:** Establish the legacy architectural limitation in one or two sharp paragraphs, then focus on modern implementations, specifications, and vulnerabilities.

### Calibrate for Senior Practitioners
* **Rule:** Maintain an audience level suited to security architects, detection engineers, and advanced researchers.
* **Avoid:** Low-level helpdesk runbook phrasing (e.g. *"Open an elevated PowerShell prompt and type..."*).
* **Instead:** Present diagnostic commands cleanly, accompanied by expected output schemas, registry paths, and programmatic verification logic.

### Typographic Restraint (No Inline Prose or Table Bolding)
* **Rule:** Reserve boldface (`**...**`) strictly for structural labels: leading labels on bulleted or numbered list items (`* **Role in the Chain:**`), callout titles (`> **Key idea.**`), and standalone glossary/definition headings.
* **Avoid:** Bolding technical terms, numbers, CVEs, code spans (`**\`code\`**`), table cells, or entire thesis clauses inside body paragraphs.
* **Instead:** Let sentence structure carry emphasis, use monospace backticks (`\`symbol\``) for identifiers, and reserve *italics* sparingly for genuine one- or two-word semantic contrast.

---

## 3. Scope Boundaries and Canonical Placement

### Strict Subsystem Ownership
* **Rule:** Each chapter strictly owns its specific subsystem. When a subsystem runs parallel to or hands off to an adjacent link, acknowledge it in one or two concise paragraphs and refer to the dedicated chapter.
* **Example:** Secure Boot owns signature verification (`LoadImage()`, authenticated variables, bootlib, LPE). It must NOT inline the full TPM extend mathematics, PCR allocation tables, or DRTM sequences; those belong exclusively to Chapter 4 (Measured Boot).

### Explain Once, Canonically (No Echo-Chamber Blocks)
* **Rule:** Every technical mechanism, certificate detail, CVE, or update program must be explained once, deeply, in its canonical section.
* **Avoid:** Introducing a fact in the body text, repeating it in an adjacent definition box, summarizing it in a table, and repeating it again in a standalone blockquote callout.
* **Discipline for Callouts:**
  * Reserve blockquote callouts (`> **...**`) exclusively for load-bearing architectural definitions, hard invariants (`> **Key idea.**`), or critical failure warnings (`> **Warning.**`).
  * Never allow a callout to echo or summarize surrounding prose.

---

## 4. Threat Modeling and Attack Catalogs

Every major chapter must ground its theoretical claims in real-world adversarial history:

1. **Structured Attack Summary Table:**
   Include a table summarizing known bypasses and exploitation milestones with standard columns:
   * **Attack / Tool**
   * **Year**
   * **Boundary Broken**
   * **Prerequisite**
   * **Adversary Mechanism**
   * **Defense / Fix Path**
2. **Gap Analysis Subsections:**
   * Treat attacks as architectural gap analysis, not exploit tutorials.
   * Explain *why* the defense failed: was the vulnerability due to a flawed implementation, a missing verification check, a signed-but-vulnerable downgrade, an unauthenticated parser below the verifier, or the lag between patching and revocation?

---

## 5. Operational Inspection and Diagnostic Commands

### Removal of Machine Evidence Ceremony
* Remove all SHA-256 hashes, capture timestamps, lab VM hostnames, and provenance tags (`🟢 CAPTURED`, `🔵 DOCUMENTED`, `🟡 EMULATED`).
* Remove dedicated "Proof on a live machine" or "Proof by documentation" headers.

### Unified Inspection Section
* Consolidate all diagnostic commands, inspection one-liners, and verification checks into a single section titled **"Inspecting and Verifying on a Running System"**.
* Format commands as clean, standard markdown code blocks with clear commentary and expected output formats.
* Keep commands concise and interactive (1 to 3 lines). Do not include large scripts, monolithic health-check automation, or sprawling parsing loops in the book text. Readers should be able to run each command directly in an interactive shell.

---

## 6. Book Architecture and Chapter Map

The consolidated manuscript contains 23 core chapters across 4 parts, an interlude, and a finale:

### Part I · Silicon (Hardware Root of Trust)
* **Chapter 1: Secure Boot** (Firmware verifier, UEFI variables, LoadImage, 2026 CA rollover, Trusted Boot handoff)
* **Chapter 2: The TPM** (Platform cryptoprocessor, PCRs, key hierarchies, endorsement keys)
* **Chapter 3: Pluton** (On-die security processor, bus-sniffing elimination, unified firmware servicing)
* **Chapter 4: Measured Boot** (SRTM, DRTM, Secured-core DMA/SMM, TCG event logs, BitLocker sealing)
* **Chapter 5: Attestation** (Remote attestation protocols, AIK, quotes, Health Attestation CSP)

### Part II · Kernel & Code (Execution & Isolation Boundaries)
* **Chapter 6: The Secure Kernel and VBS** (Hyper-V, SLAT, VTL0 vs VTL1, IUM trustlets, enclaves)
* **Chapter 7: Code Integrity and Application Control** (Authenticode, catalog files, KMCS, HVCI, WDAC)
* **Chapter 8: Protected Process Light** (PPL signer lattice, `RunAsPPL`, LSASS protection, kernel bypasses)
* **Chapter 9: Process Mitigation Policies** (Exploit mitigations: ASLR, DEP, CFG, XFG, Intel CET)

### Part III · Credentials & Access (Identity, Data Custody, & PKI)
* **Chapter 10: Windows Access Control, Integrity Levels, and Impersonation** (Tokens, SIDs, DACLs, MIC, SeImpersonate)
* **Chapter 11: Data Protection and Local Secret Custody** (BitLocker, XTS-AES, CNG KeyIso, DPAPI, App-Bound Encryption, Recall enclaves)
* **Chapter 12: Credential Guard and LSASS Isolation** (LSASS threat model, LsaIso trustlet, Pass-the-Challenge)
* **Chapter 13: The Death of NTLM** (NTLM wire protocol, NetNTLM/DNS reflection, Extended Protection for Authentication)
* **Chapter 14: Kerberos and Ticket Forgery** (Kerberos protocol, PAC validation, KRBTGT, Golden/Diamond/Sapphire tickets)
* **Chapter 15: Enterprise PKI, Service Identities, and Hybrid Bridges** (AD CS ESC1-16, Shadow Credentials, Windows LAPS, dMSA BadSuccessor, Entra Connect)
* **Chapter 16: Pass-the-Hash to Pass-the-PRT** (Credential theft evolution, Primary Refresh Token in Entra ID)
* **Chapter 17: Windows Hello and Passkeys** (Biometric pipeline, ESS, FIDO2/CTAP2 ceremonies, WebAuthn)

### Interlude · Watching the Chain
* **Chapter 18: ETW: The EDR Substrate** (Event Tracing for Windows, EtwTi, Windows Resiliency Initiative, telemetry evasion)

### Part IV · Cloud (Enterprise Session, Agentic, & Confidential Enforcement)
* **Chapter 19: Zero Trust** (Device health attestation, conditional access evaluation)
* **Chapter 20: Continuous Access Evaluation** (Real-time token revocation, push vs pull session enforcement)
* **Chapter 21: Workload and AI Agent Security** (Agent Workspace, local Agent SIDs, signed MCP, Microsoft Entra Agent ID, EchoLeak XPIA)
* **Chapter 22: Confidential VMs** (Hardware-isolated VMs, AMD SEV-SNP, Intel TDX, vTPM attestation, Battering RAM)

### Finale · When the Chain Snaps
* **Chapter 23: When the Chain Snaps: Storm-0558** (MSA signing key compromise, CVE-2025-55241 Actor Tokens, July 2026 SFI completion)

---

## 7. Specific Anti-Patterns and Editorial Laws

These seventeen laws address specific failure modes identified across early manuscript drafts. They are absolute requirements for all chapter revisions:

### Law 1: Forward Subsystem Pre-emption is Forbidden
* **Anti-Pattern:** An upstream chapter writing extensive prose, architecture diagrams, or case studies for a subsystem owned by a downstream chapter (for example: Chapter 2 spending a third of its text detailing Pluton, or Chapter 1 inlining the full Measured Boot PCR allocation table).
* **The Rule:** If a subsystem is covered in a subsequent chapter, reference it only as a one-sentence handoff. Never duplicate its architecture, comparison tables, or vendor politics. Let every chapter own its thesis exclusively.

### Law 2: Strict Section Sequencing (Probes Never Interrupt Architecture)
* **Anti-Pattern:** Placing diagnostic commands, PowerShell snippets, or verification checks in the middle of architectural explanations or before attack breakdowns.
* **The Rule:** All chapters must follow a single, immutable section order:
  1. Overview
  2. The Problem & Threat Model
  3. Architecture & Core Mechanisms
  4. Attack Catalog & Gap Analysis
  5. Theoretical Limits & Invariants
  6. Inspecting and Verifying on a Running System
  7. Summary & Handoff
  *Diagnostic inspection commands appear exclusively in Section 6.*

### Law 3: Causal Ordering (Threat Before Mitigation)
* **Anti-Pattern:** Prescribing a hardening step or mentioning a mitigation before the adversary technique or vulnerability has been introduced.
* **The Rule:** Never reference a countermeasure (e.g. preboot PIN for bus sniffing) before the underlying threat (LPC bus sniffing) has been analyzed in the threat model or attack catalog.

### Law 4: Grounded in Deployed Windows Architecture (No Speculative Draft Math)
* **Anti-Pattern:** Spending pages calculating byte-level parameter sizes of draft cryptographic standards (e.g. NIST ML-DSA buffer arithmetic in TPM NVRAM) that Windows does not currently ship or use.
* **The Rule:** Focus strictly on how modern Windows builds, enforces, and verifies trust today. When discussing emerging frontiers (PQC, confidential computing, or future agent protocols), state the architectural challenge and migration path cleanly, avoiding detached mathematical derivations of unadopted draft standards.

### Law 5: Tone of Peer-to-Peer Authority (Ban Pedantic Gimmicks)
* **Anti-Pattern:** Labeling insights as `> **Aha #1:**` or using rhetorical hand-holding (e.g. *"The conclusion is the part most engineers skip"*).
* **The Rule:** Treat the reader as an engineering peer. State architectural takeaways plainly, frame key invariants neutrally as `> **Key idea.**`, and eliminate conversational gimmicks.

### Law 6: The Direct-Ancestor Historical Boundary
* **Anti-Pattern:** Lengthy retrospectives on ancient computing lore, 1980s DOS boot viruses, or obsolete policy debates (e.g. 2002 Palladium vs Stallman DRM controversies).
* **The Rule:** Historical context is permitted only when it directly explains why a current Windows security primitive exists in its present form. Limit pre-history to one or two sharp paragraphs that establish the legacy limitation, then transition immediately to modern architecture.

### Law 7: Platform Scope Boundary (Windows Trust vs. Datacenter / Ecosystem Periphery)
* **Anti-Pattern:** Detouring into out-of-band datacenter chassis security (BMCs, Project Cerberus, Caliptra) or non-Windows consumer architectures (Apple SEP, Google Titan) that do not directly participate in the Windows trust chain.
* **The Rule:** Content must directly govern or support the Windows operating system trust model. Do not include out-of-band server hardware roots of trust or competing mobile ecosystems unless an architectural decision in Windows cannot be understood without it.

### Law 8: The Motivation Principle (Eliminate Historical Recaps)
* **Anti-Pattern:** When Chapter N solves an architectural weakness identified in Chapter N-1, re-narrating the historical attacks, exploit mechanics, or tool histories in full detail.
* **The Rule:** Never repeat historical attack narratives across consecutive chapters. State the invariant change in a single sentence (e.g. eliminating the exposed inter-chip bus by moving the security processor onto the CPU die), cross-reference the preceding chapter, and proceed immediately to the new mechanism.

### Law 9: Concise Diagnostics over Monolithic Scripts
* **Anti-Pattern:** Inlining large multi-page PowerShell scripts, custom parsing loops, or sprawling utility programs inside chapter text.
* **The Rule:** Inspection examples must be simple 1-3 line terminal or PowerShell commands that an engineer or analyst can execute immediately in an interactive shell. If a complex diagnostic is necessary, reference the native built-in utility or schema rather than printing a script harness.

### Law 10: Prohibition of Pipeline and Tooling Artifacts in Prose
* **Anti-Pattern:** Mentioning web scraping difficulties, crawler User-Agent blocks, broken external URLs, paywalls, or HTTP status codes (such as HTTP 403 on TCG sites) in chapter text.
* **The Rule:** Write with clean, permanent authority based on normative specifications and official documentation. Never expose research tooling friction or manuscript build mechanics to the reader.

### Law 11: Ban "Recap / Chapter Ownership" Callout Blocks
* **Anti-Pattern:** Interrupting prose with meta-commentary callouts declaring chapter ownership (e.g. `> **[Concept], recap.** Owned by Chapter X...`).
* **The Rule:** Concepts flow naturally across chapters. Terminology is either used directly in context or accompanied by a brief parenthetical cross-reference `(Chapter 2)`. Do not hold editorial meetings about chapter boundaries on the published page.

### Law 12: Production Reality Over Academic Curiosities (No Ghost Architecture Chapters)
* **Anti-Pattern:** Allowing a failed, optional, or non-deployed standard (such as DAA/ECDAA, or speculative cryptographic proposals) to consume the majority of a chapter while the actual shipping Windows system (e.g. Azure Attestation, Health Attestation CSP, AIK enrollment, quote validation) is starved of detail.
* **The Rule:** Chapters must dedicate the overwhelming majority of their depth to shipping, deployed Windows production architecture. Non-deployed alternatives belong strictly in a focused subsection or gap analysis explaining why production adopted a different operational trade-off.

### Law 13: Ban "Audience Role-Play" Summaries
* **Anti-Pattern:** Concluding chapters with persona-based advice blocks (e.g. *"For a platform engineer..."*, *"For an academic researcher..."*, *"For a policymaker..."*).
* **The Rule:** Maintain a single, rigorous engineering voice calibrated for senior systems and security practitioners. Do not fragment the technical conclusion into disparate persona runbooks.

### Law 14: Prohibition of Fictional and Dramatized Vignettes
* **Anti-Pattern:** Opening sections with dramatized fictional characters, clocks, or red-team narratives (e.g. *"It is 3:14 a.m. on a 2026 Windows 11 box..."*, *"At 06:00 on a Tuesday in March 2024, an administrator at a 500-seat law firm..."*).
* **The Rule:** Ground every chapter immediately in the technical problem, architectural invariant, or documented public incident (e.g. Stuxnet, Storm-0558, BlackLotus, or the original Mimikatz release). Never invent narrative fiction to illustrate an engineering concept.

### Law 15: Canonical Attack Analysis (Eliminate Scattered Mention Fatigue)
* **Anti-Pattern:** Dropping names of prominent exploits (such as Bitpixie, Mimikatz, PetitPotam, or Capcom.sys) 8 to 10 times across introductory sections, trust ledgers, and sidebars before they are ever explained.
* **The Rule:** An exploit or CVE must be mentioned in passing only with a concise cross-reference, and then systematically analyzed in full exactly once within its canonical home chapter's Attack Catalog & Gap Analysis section.

### Law 16: Decouple Cryptographic Validity from Resource Authorization
* **Anti-Pattern:** Conflating signature verification with authorization policy (e.g. assuming a valid Authenticode signature implies driver safety, or assuming a valid JWT signature implies permission to read enterprise mail).
* **The Rule:** Every chapter analyzing signed artifacts (PE drivers, Kerberos PACs, SAML assertions, JWTs, attestation quotes) must explicitly separate cryptographic validity ("was this signed by key K?") from authorization policy ("is key K permitted to access resource R?").

### Law 17: Coherent Synthesis for Merged Subsystems (No Monster Splices)
* **Anti-Pattern:** Merging multi-chapter sequences (e.g. 05+07+17 for VBS/Secure Kernel, 06+20+21 for Code Integrity, 25+26+27 for Access Control) by simply concatenating three old texts into a single sprawling file.
* **The Rule:** Merged chapters must be rewritten as a single unified narrative following the standard 7-section progression. Eliminate duplicate pre-histories, harmonize definitions, and combine all diagnostics into a single concise inspection section.

