# How to Read This Book

This book constructs one continuous systems-engineering argument across
twenty-three numbered chapters organized into four parts, an observability
interlude, and a finale, preceded by a [Prologue](../chapters/00-prologue.md)
and a [Foundations](../chapters/00b-foundations.md) primer.

## Structure of the Chain

- **Part I · Silicon ([Chapter 1](../chapters/16-secure-boot.md) to [Chapter 5](../chapters/04-attestation.md)):** Hardware and firmware roots of
  trust: UEFI Secure Boot ([Chapter 1](../chapters/16-secure-boot.md)), the Discrete and Firmware TPM ([Chapter 2](../chapters/01-tpm.md)),
  Microsoft Pluton ([Chapter 3](../chapters/02-pluton.md)), Measured Boot ([Chapter 4](../chapters/03-measured-boot.md)), and Remote
  Attestation ([Chapter 5](../chapters/04-attestation.md)).
- **Part II · Kernel & Code ([Chapter 6](../chapters/05-secure-kernel.md) to [Chapter 9](../chapters/19-mitigations.md)):** Hypervisor-enforced
  memory and code isolation: Virtualization-Based Security, the Secure Kernel,
  and `VTL1` Trustlets ([Chapter 6](../chapters/05-secure-kernel.md)), Code Integrity, Authenticode, and
  Application Control ([Chapter 7](../chapters/06-code-integrity.md)), Protected Process Light ([Chapter 8](../chapters/18-ppl.md)), and
  Process Mitigation Policies ([Chapter 9](../chapters/19-mitigations.md)).
- **Part III · Credentials & Access ([Chapter 10](../chapters/25-access-control.md) to [Chapter 17](../chapters/12-hello.md)):** Identity,
  tokens, data custody, and enterprise PKI: Windows Access Control, Integrity
  Levels, and Service Impersonation ([Chapter 10](../chapters/25-access-control.md)), Data Protection and Local
  Secret Custody ([Chapter 11](../chapters/30-data-protection.md)), Credential Guard and `LSASS` Isolation
  ([Chapter 12](../chapters/08-credential-guard.md)), The Death of `NTLM` ([Chapter 13](../chapters/09-ntlm.md)), Kerberos and Ticket Forgery
  ([Chapter 14](../chapters/10-kerberos.md)), Enterprise PKI, Service Identities, and Hybrid Bridges
  ([Chapter 15](../chapters/31-enterprise-pki.md)), `Pass-the-Hash` to `Pass-the-PRT` ([Chapter 16](../chapters/11-pth-prt.md)), and Windows
  Hello and Passkeys ([Chapter 17](../chapters/12-hello.md)).
- **Interlude · Watching the Chain ([Chapter 18](../chapters/28-etw.md)):** Event Tracing for Windows
  (`ETW`), `EtwTi`, the Windows Resiliency Initiative, and the kernel-to-user
  telemetry substrate beneath modern EDR.
- **Part IV · Cloud ([Chapter 19](../chapters/13-zero-trust.md) to [Chapter 22](../chapters/29-confidential-vms.md)):** Extending endpoint trust off
  the machine: Zero Trust and Conditional Access ([Chapter 19](../chapters/13-zero-trust.md)), Continuous
  Access Evaluation ([Chapter 20](../chapters/14-cae.md)), Workload and AI Agent Security
  ([Chapter 21](../chapters/32-agent-security.md)), and Azure Confidential VMs ([Chapter 22](../chapters/29-confidential-vms.md)).
- **Finale · When the Chain Snaps ([Chapter 23](../chapters/15-storm0558.md)):** The July 2023 `Storm-0558`
  intrusion, where every endpoint and session link held intact while a stolen
  cloud signing key and a missing cross-tier issuer check broke the top of the
  chain.

## Anatomy of Every Chapter

Every numbered chapter ([Chapter 1](../chapters/16-secure-boot.md) through [Chapter 23](../chapters/15-storm0558.md)) follows the same
predictable progression so readers can compare subsystems directly or locate
specific reference material immediately:

1. **Overview:** Five standardized coordinates defining the subsystem's role in
   the chain, core security invariant, Trusted Computing Base (`TCB`), primary
   failure modes, and architectural handoff.
2. **Core Engineering Problem & Threat Model:** The concrete systems failure the
   mechanism was engineered to solve and the adversary capabilities in scope.
3. **Architectural Deep Dive:** Step-by-step data structures, cryptographic
   bindings, kernel enforcement paths, and wire protocols, anchored to primary
   specifications in the [References](../back-matter/70-references.md).
4. **Attack Catalog & Gap Analysis:** A structured six-column attack matrix paired
   with focused architectural analyses of why each bypass succeeded and what closed
   it.
5. **Theoretical Limits & Structural Invariants:** Mathematical and architectural
   ceilings, systematically separating cryptographic validity from authorization
   and safety.
6. **Inspecting and Verifying on a Running System:** Concise, non-destructive
   PowerShell, Win32, WMI/CIM, and cloud CLI queries to audit live enforcement
   state rather than policy intent.
7. **Summary & Handoff:** Synthesis of guarantees preserved and explicit routing of
   remaining exposures to the chapters ahead.

## Verifying on Live Systems

All diagnostic commands are consolidated inside each chapter's **Inspecting and
Verifying on a Running System** section so architectural prose remains clean and
uninterrupted. Queries target modern Windows 11 (`22H2` through `25H2`), Windows
Server 2022/2025, and Microsoft Graph / Azure CLI environments; treat architectural
invariants as durable and exact build numbers, policy bitmasks, and cloud SKU
surface names as snapshots verified against the cited documentation. Cross-tier
acronyms and terms are indexed in the [Glossary](../back-matter/80-glossary.md)
and [Index](../back-matter/95-index.md).
