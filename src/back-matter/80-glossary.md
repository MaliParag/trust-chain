# Glossary

Alphabetical reference across all four parts of the Windows trust chain.

**ALPC (Advanced Local Procedure Call).** High-speed inter-process communication
primitive in the NT kernel; in Credential Guard ([Chapter 11](../chapters/08-credential-guard.md)), `VTL0` `lsass.exe`
requests cryptographic operations from `VTL1` `LsaIso.exe` across a mediated channel
without reading raw keys.

**Attestation.** Cryptographic proof of platform or key state signed by a
hardware-rooted key (`TPM AIK`, `AMD VCEK`, or `Intel TDX` Quoting Enclave) for a
remote verifier ([Chapter 5](../chapters/04-attestation.md) and [Chapter 19](../chapters/29-confidential-vms.md)).

**Authenticode.** Microsoft's code-signing format (`PKCS #7` `SignedData` over a
PE structural hash, embedded inline or in `.cat` catalogs, [Chapter 7](../chapters/06-code-integrity.md)).

**BYOVD (Bring Your Own Vulnerable Driver).** Loading a legitimately signed
third-party kernel driver containing a memory read/write flaw to gain `VTL0`
Ring 0 execution, bypassing `PPL` and blinding kernel `ETW` unless blocked by
`HVCI` and the Vulnerable Driver Blocklist ([Chapter 7](../chapters/06-code-integrity.md), [Chapter 8](../chapters/18-ppl.md), and [Chapter 16](../chapters/28-etw.md)).

**CAE (Continuous Access Evaluation).** Out-of-band push channel from Microsoft
Entra ID (standardized vendor-neutrally as `OpenID SSF 1.0` / `CAEP 1.0`) enabling
participating Resource Providers to reject revoked or IP-shifted OAuth tokens via
`HTTP 401` `insufficient_claims` challenges ([Chapter 18](../chapters/14-cae.md)).

**Conditional Access.** Microsoft Entra ID's `NIST SP 800-207` Policy Decision
Point evaluating user, authentication strength, `PRT` device identity, MDM
compliance, and risk signals before issuing cloud tokens ([Chapter 17](../chapters/13-zero-trust.md)).

**Confidential VM (CVM).** Public-cloud virtual machine (`AMD SEV-SNP` or `Intel
TDX`) whose DRAM and registers are encrypted inline by the CPU and bound via
`RMP`/`PAMT` integrity tables so the host hypervisor is excluded from the memory
`TCB` ([Chapter 19](../chapters/29-confidential-vms.md)).

**Credential Guard.** `VBS` feature isolating `NTOWF` hashes, Kerberos `TGT`
session keys, and domain credentials inside `VTL1` `LsaIso.exe` ([Chapter 11](../chapters/08-credential-guard.md)).

**DPAPI (Data Protection API).** User- and machine-scoped symmetric encryption
subsystem protecting local vaults, certificates, and browser cookies ([Chapter 11](../chapters/08-credential-guard.md) and [Chapter 14](../chapters/11-pth-prt.md)).

**ELAM (Early Launch Antimalware).** Boot-start driver initialized by `ntoskrnl`
before third-party drivers to adjudicate boot-driver signatures and anchor
`Antimalware-PPL` user-mode services ([Chapter 1](../chapters/16-secure-boot.md), [Chapter 8](../chapters/18-ppl.md), and [Chapter 16](../chapters/28-etw.md)).

**ESS (Enhanced Sign-in Security).** Hardware-isolated Windows Hello biometric
architecture pairing secure camera/sensor buses (`MIPI`, `SDCP`) with the `VTL1`
`BioIso.exe` trustlet ([Chapter 15](../chapters/12-hello.md)).

**EtwTi (`Microsoft-Windows-Threat-Intelligence`).** Kernel-emitted `ETW`
provider (`{f4e1897c-bb5d-5668-f1d8-040f4d8dd344}`) firing inside `ntoskrnl.exe`
on memory-modifying syscalls and restricted to `Antimalware-PPL` consumers
([Chapter 16](../chapters/28-etw.md)).

**HVCI (Hypervisor-Protected Code Integrity).** `VBS` enforcement of `W^X` and
signature verification over `VTL0` kernel pages via `SLAT` tables ([Chapter 6](../chapters/05-secure-kernel.md) and [Chapter 7](../chapters/06-code-integrity.md)).

**Kerberoasting (`T1558.003`).** Requesting `TGS-REP` service tickets for SPN
accounts and cracking password-derived ciphertexts (especially `enctype 23`
`RC4-HMAC`) offline, mitigated by `gMSA`/`dMSA` and `AES`-only enforcement
([Chapter 13](../chapters/10-kerberos.md)).

**KRBTGT (`RID 502`).** Built-in Active Directory account whose symmetric key set
encrypts and signs every `TGT` and `[MS-PAC]` in the domain ([Chapter 13](../chapters/10-kerberos.md)).

**LSASS (`lsass.exe`).** Local Security Authority Subsystem Service hosting
authentication packages (`msv1_0`, `kerberos`, `cloudap`, `schannel`) in `VTL0`
([Chapter 11](../chapters/08-credential-guard.md) to [Chapter 14](../chapters/11-pth-prt.md)).

**Measured Boot.** Unconditional hash-extension (`TPM2_PCR_Extend`) of every boot
component and configuration datum into `TPM` `PCRs` and the `WBCL` log ([Chapter 4](../chapters/03-measured-boot.md)).

**MIC (Mandatory Integrity Control).** Integrity-level lattice (`Untrusted`,
`Low`, `Medium`, `High`, `System`) evaluated before `DACLs` to enforce `No-Write-Up`
process and UI (`UIPI`) isolation ([Chapter 10](../chapters/25-access-control.md)).

**NTOWF (NT One-Way Function).** Unsalted `MD4(UTF-16LE(password))` digest serving
as both the `NTLM` secret and `Kerberos` `RC4-HMAC` key ([Chapter 12](../chapters/09-ntlm.md) to [Chapter 14](../chapters/11-pth-prt.md)).

**OpenHCL.** Microsoft's open-source Rust paravisor running inside a Confidential
VM (`VMPL0` on `SEV-SNP` or `L1 TD` on `TDX`) to synthesize devices and a `vTPM`
without trusting the cloud host ([Chapter 19](../chapters/29-confidential-vms.md)).

**PAC (Privilege Attribute Certificate).** `[MS-PAC]` structure inside Kerberos
tickets carrying user/group `SIDs` and up to four cryptographic signatures
(`Server`, `KDC`, `Ticket`, and `KB5020805` `Full PAC`) ([Chapter 13](../chapters/10-kerberos.md)).

**Passkey (`WebAuthn` / `CTAP 2.x`).** Discoverable FIDO2 asymmetric credential
signing origin-bound (`clientDataJSON.origin` + `SHA256(rpId)`) assertions; either
device-bound (`BE=0`, `NIST AAL3`-eligible) or synced (`BE=1`, `AAL2`) ([Chapter 15](../chapters/12-hello.md)).

**PCR (Platform Configuration Register).** Extend-only `TPM` digest register
recording ordered boot measurements ([Chapter 2](../chapters/01-tpm.md) and [Chapter 4](../chapters/03-measured-boot.md)).

**Pluton.** Microsoft-designed security processor integrated directly onto AMD,
Intel, and Qualcomm CPU dies ([Chapter 3](../chapters/02-pluton.md)).

**PPL (Protected Process Light).** Kernel `_EPROCESS.Protection` lattice gating
cross-process handle access Rights by code-signing level ([Chapter 8](../chapters/18-ppl.md)).

**PRT (Primary Refresh Token).** 90-day rolling Microsoft Entra SSO artifact
brokered by `cloudap.dll` and paired with a `TPM`-protected session key ([Chapter 14](../chapters/11-pth-prt.md)).

**RBCD (Resource-Based Constrained Delegation).** Kerberos `S4U2Self` +
`S4U2Proxy` delegation controlled via `msDS-AllowedToActOnBehalfOfOtherIdentity`
on the target computer object ([Chapter 13](../chapters/10-kerberos.md)).

**RMP / PAMT.** Hardware page-ownership metadata tables in `AMD SEV-SNP` (`RMP`)
and `Intel TDX` (`PAMT`) preventing host hypervisor ciphertext-remapping attacks
([Chapter 19](../chapters/29-confidential-vms.md)).

**Secure Boot.** `UEFI` signature enforcement blocking untrusted pre-OS binaries
([Chapter 1](../chapters/16-secure-boot.md)).

**Secure Kernel (`securekernel.exe`).** Micro-kernel executing in `VTL1` under
`VBS` to enforce `HVCI`, mediate `SLAT` permissions, and host isolated trustlets
([Chapter 6](../chapters/05-secure-kernel.md)).

**SLAT (Second-Level Address Translation).** CPU nested paging (`Intel EPT` /
`AMD NPT`) used by Hyper-V both for VMs and to isolate `VTL1` RAM from `VTL0`
([Chapter 6](../chapters/05-secure-kernel.md)).

**Strong Certificate Mapping (`KB5014754`).** Active Directory `PKINIT` rule
binding X.509 certificates to principal `SIDs` via OID `1.3.6.1.4.1.311.25.2` to
defeat SAN spoofing ([Chapter 13](../chapters/10-kerberos.md) and [Chapter 14](../chapters/11-pth-prt.md)).

**TCB (Trusted Computing Base).** Every hardware, firmware, and software element
that must operate honestly and bug-free for a security guarantee to hold
([Foundations](../chapters/00b-foundations.md)).

**WDAC / App Control for Business.** Kernel and user-mode policy engine (`ci.dll`)
restricting executable code and scripts to approved signers and hashes ([Chapter 7](../chapters/06-code-integrity.md)).
