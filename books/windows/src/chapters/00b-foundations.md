# Foundations

## A Shared Systems Vocabulary

The Windows trust chain spans four engineering disciplines that rarely sit at the
same table: platform firmware and silicon, operating-system kernel architecture,
enterprise authentication protocols, and cloud control planes. A firmware
engineer fluent in `PCR` bank allocations may seldom inspect a Kerberos
`[MS-PAC]` checksum, while an identity architect designing Conditional Access
policies may never trace a `VTL0`-to-`VTL1` `VMCALL`. Before [Chapter 1](16-secure-boot.md)
begins at the CPU reset vector, this primer establishes the shared concepts and
vocabulary that connect all twenty-three chapters into a single argument.

## Trust, the TCB, and Serviced Boundaries

Every chapter in this book evaluates mechanisms through three structural ideas:
the Trusted Computing Base, the root of trust, and the serviced security
boundary. The *Trusted Computing Base* (`TCB`) is the complete set of hardware,
firmware, and software components whose malfunction or compromise breaks a
specific security invariant. Shrinking the `TCB` for high-value secrets is the
central architectural lever of modern Windows. When Credential Guard
([Chapter 12](08-credential-guard.md)) moves domain password hashes out of `lsass.exe`, it removes
the multi-million-line `VTL0` NT kernel and every third-party kernel driver from
the `TCB` protecting those credentials, leaving only the Hyper-V hypervisor, the
compact `VTL1` Secure Kernel, and the `LsaIso.exe` trustlet.

Every `TCB` terminates downward in a *root of trust*: a foundational component
whose integrity must be assumed rather than verified by lower software because
nothing executes beneath it. On contemporary x86 and ARM64 PCs, roots of trust
live in immutable mask ROM and one-time-programmable silicon fuses (`Intel Boot
Guard`, `AMD Hardware Validated Boot`, `TPM 2.0`, and `Microsoft Pluton`),
anchoring verification before mutable flash code runs.

Surrounding those components are *security boundaries* as defined in the
Microsoft Security Servicing Criteria. A serviced boundary separates domains of
distinct trust: `Ring 3` user processes from `Ring 0` kernel memory, guest
virtual machines from the host hypervisor, `VTL0` normal world from `VTL1` secure
world, and cross-machine network interfaces. Vulnerabilities that cross a
serviced boundary receive mandatory security patches and CVEs; features that sit
inside a single trust domain (such as default same-user `UAC` or discretionary
`AppLocker` rules against a local administrator) provide defense in depth only
when backed by a true boundary beneath them.

## Silicon and Pre-OS Roots

Platform startup divides responsibility between active prevention and passive
measurement. `UEFI Secure Boot` ([Chapter 1](16-secure-boot.md)) acts as the pre-OS gatekeeper,
requiring every EFI binary (`bootmgfw.efi`, `winload.efi`, and PCIe Option ROMs)
to carry a valid `Authenticode` signature chaining to the allowlist database
(`DB`) while remaining absent from the revocation database (`DBX`), governed up
to the Platform Key (`PK`) and Key Exchange Keys (`KEK`).

Whereas Secure Boot decides whether early code may run, the `Trusted Platform
Module` (`TPM 2.0`, [Chapter 2](01-tpm.md)) and on-die `Microsoft Pluton` processor
([Chapter 3](02-pluton.md)) provide tamper-resistant key custody, dictionary-attack
lockouts, and `Platform Configuration Registers` (`PCRs`). Across `Measured Boot`
([Chapter 4](03-measured-boot.md)), each stage hashes the next before transferring control and
extends that digest irreversibly into `TPM` `PCRs`:

$$\text{PCR}_{\text{new}} = H(\text{PCR}_{\text{old}} \parallel \text{digest})$$

Local *sealing* binds secrets (such as a `BitLocker` Volume Master Key) to an
expected `PCR` digest so the `TPM` releases the key only when the boot sequence
matches. *Remote attestation* ([Chapter 5](04-attestation.md)) signs those `PCR` values alongside
the Windows Boot Configuration Log (`WBCL`) using a hardware-rooted Attestation
Identity Key (`AIK`), turning local boot history into cryptographic evidence a
remote verifier can appraise.

## Kernel Isolation and Code Integrity

On classic x86-64 hardware, applications execute in `Ring 3` and `ntoskrnl.exe`
shares `Ring 0` with every loaded device driver, meaning a single memory-corrupting
third-party driver compromises all of traditional kernel RAM. `Virtualization-Based
Security` (`VBS`, [Chapter 6](05-secure-kernel.md)) breaks that all-or-nothing kernel model by
placing the Hyper-V hypervisor beneath the OS and using Second-Level Address
Translation (`SLAT`) to partition a single machine into orthogonal Virtual Trust
Levels. Normal `ntoskrnl.exe` and applications inhabit `VTL0`, while
`securekernel.exe` and Isolated User Mode (`IUM`) trustlets (`LsaIso.exe`,
`BioIso.exe`, `KeyIso`, and `VBS Enclaves`) inhabit `VTL1`, whose physical memory
pages are unmapped in `VTL0`'s nested page tables.

Atop `VBS`, `Code Integrity` ([Chapter 7](06-code-integrity.md)) validates `Authenticode` Portable
Executable (`PE`) signatures and `.cat` catalogs. `Hypervisor-Protected Code
Integrity` (`HVCI`) moves kernel `W^X` page-permission enforcement into `VTL1` so
even an arbitrary `VTL0` kernel write cannot mint executable shellcode, while `App
Control for Business` (`WDAC`) restricts user and kernel binaries to approved
publishers, leaving Bring Your Own Vulnerable Driver (`BYOVD`) as the primary
residual battleground. Within `VTL0` user mode, `Protected Process Light` (`PPL`,
[Chapter 8](18-ppl.md)) ranks sensitive system and antimalware processes inside
`_EPROCESS.Protection` to strip `PROCESS_VM_READ` and `PROCESS_VM_WRITE` from
unprotected administrative handles, while `Process Mitigation Policies`
([Chapter 9](19-mitigations.md)) enforce `ACG`, forward-edge `CFG`/`XFG`, and hardware `CET` Shadow
Stacks against in-process memory corruption.

## Access Control, Data Custody, and Credentials

Once code is running, the kernel Security Reference Monitor governs local object
access through `SeAccessCheck` ([Chapter 10](25-access-control.md)). Every process and thread
carries an Access Token encoding user and group Security Identifiers (`SIDs`),
privileges such as `SeDebugPrivilege` and `SeImpersonatePrivilege`, `AppContainer`
sandbox capabilities, and a Mandatory Integrity Level (`Low`, `Medium`, `High`,
or `System`) evaluated ahead of Discretionary Access Control Lists (`DACLs`).
Persistent data and application keys rest on `BitLocker` (`fvevol.sys`), `DPAPI`
and `DPAPI-NG`, and `VTL1`-backed `CNG KeyIso` ([Chapter 11](30-data-protection.md)).

Network authentication flows through pluggable Security Support Providers (`SSPs`)
hosted inside `lsass.exe` and split across `VTL1` by `Credential Guard`
([Chapter 12](08-credential-guard.md)). Legacy `NTLM` (`msv1_0.dll`, [Chapter 13](09-ntlm.md)) computes
challenge-response proofs directly over the unsalted `MD4(UTF-16LE(password))`
`NTOWF` hash, making stored hashes password-equivalent (`Pass-the-Hash`) and
exposing unbound sessions to relay until `IAKerb` and `Local KDC` complete its
retirement. Active Directory `Kerberos` (`kerberos.dll`, [Chapter 14](10-kerberos.md)) replaces
hash challenges with Key Distribution Center (`KDC`) tickets carrying `[MS-PAC]`
authorization data signed under the realm `krbtgt` (`RID 502`) key, operating
alongside `AD CS` public-key infrastructure (`PKINIT`), `Windows LAPS`, and
managed service accounts (`gMSA` and `dMSA`) in [Chapter 15](31-enterprise-pki.md). For hybrid
and cloud single sign-on, `cloudap.dll` ([Chapter 16](11-pth-prt.md)) brokers `TPM`-bound
Primary Refresh Tokens (`PRTs`), while `Windows Hello` and `WebAuthn` passkeys
([Chapter 17](12-hello.md)) replace shared secrets altogether with gesture-gated asymmetric
signatures bound to relying-party origins.

## Telemetry, Cloud Policy, AI Agents, and Confidential Compute

Across all host layers, `Event Tracing for Windows` (`ETW`, [Chapter 18](28-etw.md)) feeds
lock-free per-CPU kernel ring buffers, combining user-mode runtime providers
(`AMSI`, `PowerShell`, `.NET`) with kernel-emitted
`Microsoft-Windows-Threat-Intelligence` (`EtwTi`) syscall sensors and modern
out-of-kernel endpoint security APIs.

Part IV lifts those host guarantees into the cloud. `Microsoft Entra Conditional
Access` ([Chapter 19](13-zero-trust.md)) acts as a `NIST SP 800-207` Policy Decision Point (`PDP`)
evaluating identity, `PRT` device binding, MDM compliance, and Defender XDR risk
at token issuance (`t = 0`), while `Continuous Access Evaluation` (`CAE`,
[Chapter 20](14-cae.md)) pushes mid-session revocations (`t > 0`) to Resource Providers via
`HTTP 401` claims challenges. Because non-human workloads and nondeterministic AI
agents break interactive human session assumptions, Windows 11 `Agent Workspace`
and `Microsoft Entra Agent ID` ([Chapter 21](32-agent-security.md)) isolate agent execution and
bound `On-Behalf-Of` delegation against confused-deputy prompt injection. Finally,
`Azure Confidential VMs` ([Chapter 22](29-confidential-vms.md)) pair `AMD SEV-SNP` and `Intel TDX`
memory encryption with `OpenHCL` `vTPM` attestation to exclude the cloud host
hypervisor from the guest memory `TCB`, setting the stage for [Chapter 23](15-storm0558.md)'s
analysis of `Storm-0558`, where a compromised cloud signing key and an omitted
issuer check snapped the top of the chain while every lower link held.

## Primary Sources and Live Verification

Every architectural claim in this book is cited inline (`[N]`) to the master
bibliography in the [References](../back-matter/70-references.md), prioritizing normative specifications
(`UEFI`, `TCG TPM 2.0`, `IETF RFCs`, `W3C WebAuthn`, `NIST SPs`, `[MS-*]`
protocol documents, and `Microsoft Learn`), peer-reviewed papers, and official
incident post-mortems (`CSRB`, `CISA`). Rather than asking you to take prose
descriptions on faith, the sixth section of every chapter (*Inspecting and
Verifying on a Running System*) provides concise, read-only PowerShell, Win32,
registry, and cloud CLI queries so you can verify live enforcement state on your
own systems.

![Figure: The trust chain as one spine: a map of this book. Each part inherits its security from the part below it: Silicon roots the chain at the foundation; the Kernel and its code sit above it; Credentials and Access spend the trust those layers protect; and Cloud rides near the top, where the machine boundary becomes one signal among many. The Interlude observes every link from the side, and the Finale is what happens when a link inherits more authority than the link below it meant to grant. The argument of the entire book is the direction of the arrows: trust is inherited, never asserted.](diagrams/trust-chain-map.svg)
