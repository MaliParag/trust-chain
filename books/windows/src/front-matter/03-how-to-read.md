# How to Read This Book

This book constructs one continuous systems-engineering argument across
twenty-three numbered chapters organized into four parts, an observability
interlude, and a finale, preceded by a [Prologue](../chapters/00-prologue.md)
and a [Foundations](../chapters/00b-foundations.md) primer.

## Structure of the Chain

Part I (*Silicon*, [Chapter 1](../chapters/16-secure-boot.md) through [Chapter 5](../chapters/04-attestation.md))
establishes the hardware and pre-OS roots of trust: UEFI Secure Boot
([Chapter 1](../chapters/16-secure-boot.md)), the discrete and firmware TPM
([Chapter 2](../chapters/01-tpm.md)), on-die Microsoft Pluton
([Chapter 3](../chapters/02-pluton.md)), Measured Boot `PCR` hash chains
([Chapter 4](../chapters/03-measured-boot.md)), and Remote Attestation
([Chapter 5](../chapters/04-attestation.md)). Part II (*Kernel & Code*,
[Chapter 6](../chapters/05-secure-kernel.md) through [Chapter 9](../chapters/19-mitigations.md))
moves upward into hypervisor-enforced memory and code isolation, tracing
Virtualization-Based Security, the Secure Kernel, and `VTL1` trustlets
([Chapter 6](../chapters/05-secure-kernel.md)), Code Integrity, `Authenticode`, and
Application Control ([Chapter 7](../chapters/06-code-integrity.md)), Protected Process
Light ([Chapter 8](../chapters/18-ppl.md)), and Process Mitigation Policies
([Chapter 9](../chapters/19-mitigations.md)).

Part III (*Credentials & Access*, [Chapter 10](../chapters/25-access-control.md) through
[Chapter 17](../chapters/12-hello.md)) examines how Windows governs authorization,
persistent secrets, and network identity: Windows Access Control, Integrity
Levels, and Service Impersonation ([Chapter 10](../chapters/25-access-control.md)), Data
Protection and Local Secret Custody across `BitLocker`, `KeyIso`, and `DPAPI`
([Chapter 11](../chapters/30-data-protection.md)), Credential Guard and `LSASS` Isolation
([Chapter 12](../chapters/08-credential-guard.md)), The Death of `NTLM`
([Chapter 13](../chapters/09-ntlm.md)), Kerberos and Ticket Forgery
([Chapter 14](../chapters/10-kerberos.md)), Enterprise PKI, Service Identities, and
Hybrid Bridges ([Chapter 15](../chapters/31-enterprise-pki.md)), `Pass-the-Hash` to
`Pass-the-PRT` ([Chapter 16](../chapters/11-pth-prt.md)), and Windows Hello and Passkeys
([Chapter 17](../chapters/12-hello.md)).

Between host identity and the cloud sits an observability interlude ([Chapter 18](../chapters/28-etw.md))
devoted to Event Tracing for Windows (`ETW`), kernel `EtwTi` sensors, and the
Windows Resiliency Initiative. Part IV (*Cloud*, [Chapter 19](../chapters/13-zero-trust.md)
through [Chapter 22](../chapters/29-confidential-vms.md)) then lifts endpoint posture into
distributed policy and cloud silicon: Zero Trust and Conditional Access
([Chapter 19](../chapters/13-zero-trust.md)), Continuous Access Evaluation
([Chapter 20](../chapters/14-cae.md)), Workload and AI Agent Security across Windows 11
`Agent Workspace` and `Microsoft Entra Agent ID` ([Chapter 21](../chapters/32-agent-security.md)),
and Azure Confidential VMs ([Chapter 22](../chapters/29-confidential-vms.md)). Finally,
[Chapter 23](../chapters/15-storm0558.md) (*When the Chain Snaps: Storm-0558*) dissects the
July 2023 cloud signing-key intrusion, showing how a compromised root secret and
an omitted cross-tier issuer check bypassed every intact lower link.

## Anatomy of Every Chapter

Every numbered chapter ([Chapter 1](../chapters/16-secure-boot.md) through
[Chapter 23](../chapters/15-storm0558.md)) follows the same seven-part progression so
readers can compare subsystems directly or turn immediately to a specific layer
during an architectural review. Each chapter opens with an outlined *Overview*
card fixing five coordinates: the subsystem's role in the chain, its core
security invariant, its Trusted Computing Base (`TCB`), its primary failure
modes, and its architectural handoff. *Core Engineering Problem & Threat Model*
frames the concrete systems failure the mechanism was built to solve and the
adversary capabilities in scope, followed by *Architectural Deep Dive*, which
traces the on-disk structures, cryptographic constructions, kernel call paths,
and wire protocols anchored to normative citations in the
[References](../back-matter/70-references.md).

From construction, each chapter turns to adversarial reality. *Attack Catalog &
Gap Analysis* pairs a six-column historical bypass table with focused structural
analyses of why each exploit class succeeded and what closed it, while
*Theoretical Limits & Structural Invariants* isolates the mathematical and
operational ceilings that separate cryptographic validity from authorization and
safety. *Inspecting and Verifying on a Running System* consolidates concise,
non-destructive PowerShell, Win32, WMI/CIM, and cloud CLI queries to audit live
enforcement state rather than policy intent, and *Summary & Handoff* routes
residual exposures explicitly to the chapters ahead.

## Verifying on Live Systems

Keeping diagnostic queries inside each chapter's dedicated inspection section
allows the architectural narrative to read uninterrupted. Queries target modern
Windows 11 (`22H2` through `25H2`), Windows Server 2022 and 2025, and Microsoft
Graph or Azure CLI environments; treat architectural invariants as durable and
exact build numbers, policy bitmasks, and cloud SKU names as verified snapshots
grounded in the cited primary sources. Cross-tier acronyms and concepts are
indexed in the [Glossary](../back-matter/80-glossary.md) and
[Index](../back-matter/95-index.md).
