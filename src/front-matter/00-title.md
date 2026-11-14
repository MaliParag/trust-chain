# The Windows Trust Chain

## How Modern Windows Builds Trust from Silicon to Cloud, and Where Attackers Break It

**Parag Mali**

---

Modern Windows is not defended by any single security feature. It is defended by
a directed chain of cryptographic and architectural invariants: platform silicon
verifies firmware before releasing the reset vector, UEFI Secure Boot and
Measured Boot anchor the OS loader in a Trusted Platform Module, Hyper-V
partitions physical memory into isolated Virtual Trust Levels (`VTL0` and `VTL1`),
kernel code integrity and access tokens constrain execution, Active Directory
tickets and hardware-bound passkeys govern identity, `ETW` records telemetry, and
cloud policy engines continuously evaluate device and session state. Every link
inherits from the link beneath it, and every link fails the moment a higher
layer mistakes cryptographic validity for authorization.

### Architecture of the Book

| Section | Chapters | Scope |
|---|---|---|
| Opening | [Prologue](../chapters/00-prologue.md) · [Foundations](../chapters/00b-foundations.md) | Why trust must be inherited rather than asserted, serviced security boundaries, and shared vocabulary across all four tiers |
| Part I · Silicon | [1. Secure Boot](../chapters/16-secure-boot.md) · [2. The TPM](../chapters/01-tpm.md) · [3. Pluton](../chapters/02-pluton.md) · [4. Measured Boot](../chapters/03-measured-boot.md) · [5. Attestation](../chapters/04-attestation.md) | Hardware roots of trust, UEFI signature databases, discrete vs. firmware vs. on-die TPMs, `PCR` extend chains, and remote attestation |
| Part II · Kernel & Code | [6. The Secure Kernel and VBS](../chapters/05-secure-kernel.md) · [7. Code Integrity and Application Control](../chapters/06-code-integrity.md) · [8. Protected Process Light](../chapters/18-ppl.md) · [9. Process Mitigation Policies](../chapters/19-mitigations.md) | `SLAT`-enforced `VTL1` isolation, `IUM` trustlets, `Authenticode`, `HVCI`, `WDAC`, `_EPROCESS` signer lattices, `ACG`, `CFG`, and `CET` |
| Part III · Credentials & Access | [10. Windows Access Control, Integrity Levels, and Impersonation](../chapters/25-access-control.md) · [11. Credential Guard and LSASS Isolation](../chapters/08-credential-guard.md) · [12. The Death of NTLM](../chapters/09-ntlm.md) · [13. Kerberos and Ticket Forgery](../chapters/10-kerberos.md) · [14. Pass-the-Hash to Pass-the-PRT](../chapters/11-pth-prt.md) · [15. Windows Hello and Passkeys](../chapters/12-hello.md) | Tokens, `MIC` integrity levels, `Potato` escalation, `LsaIso.exe`, `NTLM` relay closure, `[MS-PAC]` & `krbtgt`, `CloudAP` `PRTs`, `ESS`, and `WebAuthn` |
| Interlude | [16. ETW: The EDR Substrate](../chapters/28-etw.md) | Per-CPU lock-free ring buffers, manifest fan-out, user-mode `0xC3` patching vs. kernel `EtwTi`, and `Antimalware-PPL` + `ELAM` gates |
| Part IV · Cloud | [17. Zero Trust](../chapters/13-zero-trust.md) · [18. Continuous Access Evaluation](../chapters/14-cae.md) · [19. Confidential VMs](../chapters/29-confidential-vms.md) | `NIST SP 800-207` `PDP`/`PEP` evaluation in Entra Conditional Access, `HTTP 401` `CAE` revocation, `AMD SEV-SNP`, `Intel TDX`, and `OpenHCL` |
| Finale | [20. When the Chain Snaps: Storm-0558](../chapters/15-storm0558.md) | How a stolen 2016 `MSA` signing key and a missing cross-tier `RFC 8725` issuer check forged enterprise cloud mail tokens while every lower link held |
| Back Matter | [References](../back-matter/70-references.md) · [Glossary](../back-matter/80-glossary.md) · [About This Book](../back-matter/85-about.md) · [Colophon](../back-matter/90-colophon.md) · [Index](../back-matter/95-index.md) | 876 primary-source references, cross-tier glossary, editorial methodology, build architecture, and hyperlinked subject index |

Begin with the [Prologue](../chapters/00-prologue.md) or review [How to Read This Book](../front-matter/03-how-to-read.md).
