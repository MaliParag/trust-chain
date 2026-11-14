# Foundations

## A Shared Systems Vocabulary

The Windows trust chain spans four engineering disciplines: platform firmware and
silicon, operating-system kernel architecture, enterprise authentication
protocols, and cloud control planes. Few practitioners work simultaneously in all
four. A firmware engineer fluent in `PCR` bank allocations may rarely inspect a
Kerberos `[MS-PAC]` checksum; an identity architect designing Conditional Access
policies may never trace a `VTL0`-to-`VTL1` `VMCALL`. This chapter establishes the
compact baseline vocabulary shared across the twenty-three chapters ahead.

## 1. Trust, the TCB, and Serviced Boundaries

**Trusted Computing Base (`TCB`).** The complete set of hardware, firmware, and
software components whose malfunction or compromise breaks a specific security
invariant. Shrinking the `TCB` is the primary design lever of modern Windows:
Credential Guard ([Chapter 12](08-credential-guard.md)) removes the multi-million-line `VTL0` NT kernel
and third-party driver ecosystem from the `TCB` protecting domain password hashes,
replacing them with the Hyper-V hypervisor, the tiny `VTL1` Secure Kernel, and
`LsaIso.exe`.

**Root of Trust.** A foundational component whose integrity must be assumed
rather than verified by lower software because nothing executes beneath it. Hardware
roots of trust (`Intel Boot Guard`, `AMD Hardware Validated Boot`, `TPM 2.0`,
`Microsoft Pluton`) anchor verification in immutable mask ROM and one-time-programmable
silicon fuses.

**Security Boundary.** An isolation wall defined in the *Microsoft Security
Servicing Criteria* across domains of distinct trust (`Ring 3` user mode to
`Ring 0` kernel mode, guest VM to hypervisor, `VTL0` to `VTL1`, and cross-machine
network interfaces). A vulnerability crossing a serviced security boundary earns
a CVE and a mandatory security patch; crossing a non-boundary feature requires
compensating architectural layers.

## 2. The Silicon Tier

**UEFI Secure Boot (`PK`, `KEK`, `DB`, `DBX`).** Firmware policy enforcing that
pre-OS UEFI images (`bootmgfw.efi`, `winload.efi`, Option ROMs) carry valid
`Authenticode` signatures chaining to `DB` while absent from the `DBX` revocation
list ([Chapter 1](16-secure-boot.md)). Secure Boot *prevents* unauthorized pre-OS code execution.

**Trusted Platform Module (`TPM 2.0`) and `Pluton`.** Tamper-resistant
cryptoprocessors (`ISO/IEC 11889`) generating non-exportable keys, enforcing
anti-hammering dictionary-attack lockouts, and maintaining Platform
Configuration Registers (`PCRs`, [Chapter 2](01-tpm.md) and [Chapter 3](02-pluton.md)). Discrete `dTPMs` sit on
external `SPI`/`LPC` buses; firmware `fTPMs` execute in CPU secure enclaves;
`Microsoft Pluton` integrates the security processor directly onto the CPU die.

**Measured Boot (`Extend`), Sealing, and Attestation.** Unlike `Secure Boot`
(which blocks), `Measured Boot` ([Chapter 4](03-measured-boot.md)) *records* every boot component
into `TPM` `PCRs` via one-way hash chaining:

$$\text{PCR}_{\text{new}} = H(\text{PCR}_{\text{old}} \parallel \text{digest})$$

Sealing binds a secret (such as a BitLocker Volume Master Key) so the `TPM`
unseals it only when `PCRs` match an expected boot profile. Remote Attestation
([Chapter 5](04-attestation.md)) signs `PCR` values and the `WBCL` event log with a hardware-rooted
Attestation Identity Key (`AIK`) so an external verifier can audit boot health.

## 3. The Kernel and Code-Integrity Tier

**Privilege Rings vs. Virtual Trust Levels (`VTL0` / `VTL1`).** On x86-64,
applications run in `Ring 3` (user mode) and `ntoskrnl.exe` plus drivers run in
`Ring 0` (kernel mode). Because a single vulnerable `Ring 0` driver compromises
all of normal kernel memory, Virtualization-Based Security (`VBS`, [Chapter 6](05-secure-kernel.md))
uses the Hyper-V hypervisor and CPU Second-Level Address Translation (`SLAT`)
to partition a single OS into orthogonal Virtual Trust Levels: `VTL0`
(normal `ntoskrnl.exe` and apps) and `VTL1` (`securekernel.exe` and Isolated
User Mode trustlets such as `LsaIso.exe` and `BioIso.exe`). Even `Ring 0` code
in `VTL0` cannot read or execute `VTL1` pages.

**`Authenticode`, `HVCI`, and Application Control (`WDAC`).** `Authenticode`
([Chapter 7](06-code-integrity.md)) signs Portable Executable (`PE`) structural hashes inline or via
detached `.cat` catalog files. Hypervisor-Protected Code Integrity (`HVCI`)
moves kernel page-permission enforcement into `VTL1` (`W^X` across `SLAT` tables),
while App Control for Business (`WDAC`) restricts user- and kernel-mode
execution to explicitly trusted publishers and hashes, countered offensively by
Bring Your Own Vulnerable Driver (`BYOVD`).

**Protected Process Light (`PPL`) and Exploit Mitigations.** `PPL`
([Chapter 8](18-ppl.md)) assigns signer-ranked protection levels (`WinTcb`, `Lsa`,
`Antimalware`) inside `_EPROCESS`, stripping `PROCESS_VM_READ`/`WRITE` from
unprotected administrative handles. Process Mitigation Policies ([Chapter 9](19-mitigations.md),
including `ACG`, `CFG`, and hardware `CET` Shadow Stacks) constrain memory
corruption exploitation inside individual processes.

## 4. The Access-Control and Credential Tier

**`SIDs`, Access Tokens, `DACLs`, Integrity Levels (`MIC`), and Impersonation.**
Every principal holds a Security Identifier (`SID`). Upon logon, the kernel
attaches an Access Token listing user/group `SIDs`, Privileges (such as
`SeDebugPrivilege` and `SeImpersonatePrivilege`), and a Mandatory Integrity
Level (`Low`, `Medium`, `High`, `System`) evaluated before Discretionary Access
Control Lists (`DACLs`) via `SeAccessCheck` ([Chapter 10](25-access-control.md)). Volume sectors at rest and local application key containers are protected by `BitLocker` (`fvevol.sys`), `DPAPI` / `DPAPI-NG`, and `VTL1` `CNG KeyIso` ([Chapter 11](30-data-protection.md)).

**`LSASS`, `SSPs`, `NTLM`, `Kerberos`, and `AD CS`.** `lsass.exe` hosts pluggable
Security Support Providers (`SSPs`) ([Chapter 12](08-credential-guard.md)):
* **`msv1_0.dll` (`NTLM`, [Chapter 13](09-ntlm.md)):** Challenge-response over the unsalted
  `MD4(UTF-16LE(password))` `NTOWF` hash, making the stored hash directly
  password-equivalent (`Pass-the-Hash`) and vulnerable to cross-protocol relay.
* **`kerberos.dll` (`Kerberos`, [Chapter 14](10-kerberos.md)) and `AD CS` ([Chapter 15](31-enterprise-pki.md)):** Key Distribution Center (`KDC`)
  three-phase ticket protocol (`AS`, `TGS`, `AP`) carrying `[MS-PAC]` group `SIDs`
  signed under `krbtgt` (`RID 502`), paired with Enterprise PKI (`PKINIT`) and
  managed service accounts (`gMSA` and `dMSA`).
* **`cloudap.dll` (`CloudAP`, [Chapter 16](11-pth-prt.md)):** Brokers Microsoft Entra ID
  Primary Refresh Tokens (`PRTs`) paired with `TPM`-protected session keys.
* **Windows Hello (`NGC`) and `WebAuthn` Passkeys ([Chapter 17](12-hello.md)):** Replace
  shared remote secrets with local gesture-gated (`PIN` or `ESS` biometric)
  asymmetric signatures bound to `TPM 2.0` and relying-party origins (`rpId`).

## 5. Telemetry and the Cloud Tier

**Event Tracing for Windows (`ETW` and `EtwTi`).** High-throughput, per-CPU
kernel ring-buffer event bus ([Chapter 18](28-etw.md)) uniting user-mode providers (`AMSI`,
`PowerShell`, `.NET`) with kernel-emitted `Microsoft-Windows-Threat-Intelligence`
(`EtwTi`) memory-syscall telemetry gated behind `Antimalware-PPL` + `ELAM`.

**Zero Trust (`PDP`/`PEP`), `CAE`, AI Agents, and Confidential VMs.** Microsoft Entra
Conditional Access ([Chapter 19](13-zero-trust.md)) acts as a `NIST SP 800-207` Policy Decision
Point (`PDP`) evaluating identity, `PRT` device binding, Intune compliance, and
Defender XDR risk at token issuance (`t = 0`). Continuous Access Evaluation
(`CAE`, [Chapter 20](14-cae.md)) pushes mid-session revocations (`t > 0`) to Resource
Providers via `HTTP 401` claims challenges; Windows 11 `Agent Workspace` and
`Microsoft Entra Agent ID` ([Chapter 21](32-agent-security.md)) bound non-human workloads and AI
agents against confused-deputy prompt injection; and Azure Confidential VMs
([Chapter 22](29-confidential-vms.md)) use `AMD SEV-SNP` and `Intel TDX` inline memory encryption plus
`OpenHCL` `vTPM` attestation to remove the cloud host hypervisor from the guest
`TCB`.

## 6. Primary Sources and Live Verification

Every architectural claim in this book is referenced inline (`[N]`) to the
master bibliography ([References](../back-matter/70-references.md)), prioritizing normative specifications (`UEFI`,
`TCG TPM 2.0`, `IETF RFCs`, `W3C WebAuthn`, `NIST SPs`, `[MS-KILE]`/`[MS-PAC]`,
and `Microsoft Learn`), peer-reviewed papers, and federal incident reviews
(`CSRB`, `CISA`). Rather than asking you to trust prose descriptions of Windows
internals, Section 6 of every chapter (*Inspecting and Verifying on a Running
System*) provides concise, read-only PowerShell, Win32, registry, and cloud CLI
commands so you can inspect each boundary directly on a live endpoint or tenant.

![Figure: The trust chain as one spine: a map of this book. Each part inherits its security from the part below it: Silicon roots the chain at the foundation; the Kernel and its code sit above it; Credentials and Access spend the trust those layers protect; and Cloud rides near the top, where the machine boundary becomes one signal among many. The Interlude observes every link from the side, and the Finale is what happens when a link inherits more authority than the link below it meant to grant. The argument of the entire book is the direction of the arrows: trust is inherited, never asserted.](diagrams/trust-chain-map.svg)
