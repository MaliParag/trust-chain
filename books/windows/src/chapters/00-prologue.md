# Prologue

## What "Trust" Means in Systems Engineering

Inspect the user-mode memory of `lsass.exe` on a hardened Windows 11 machine
while a domain user is signed in, and look for the `NTOWF` password hash that
lived there from Windows NT 3.1 in 1993 through Windows 8.1. You will not find
plaintext credentials. Instead, you will find an encrypted cipher blob whose
wrapping key resides across a hardware virtualization boundary inside a second,
isolated kernel that neither `NT AUTHORITY\SYSTEM` nor a Ring 0 kernel driver
can map. That absence is the visible outcome of an architectural chain that
begins before the operating system exists, anchored in keys fused into silicon
at manufacture.

This book is about how that chain is built, and how attackers break it.

A modern Windows machine is not secured by any single mitigation. It is secured
by a directed sequence of cryptographic and architectural invariants, each
enforced by a lower, smaller component on behalf of the larger layer above it.
Platform silicon verifies initial firmware before releasing the reset vector.
UEFI firmware verifies OS bootloaders against revocable signature databases and
extends cryptographic hashes of every boot input into a Trusted Platform Module.
The Hyper-V hypervisor partitions physical RAM using Second-Level Address
Translation (`SLAT`) so a tiny Secure Kernel in `VTL1` can enforce code
integrity over `VTL0` and shield credentials from `lsass.exe`. Above the kernel,
access tokens, mandatory integrity levels, volume and local key vaults, Kerberos
`[MS-PAC]` signatures, `AD CS` certificates, TPM-bound Primary Refresh Tokens,
and origin-bound `WebAuthn` passkeys govern identity, while cloud Policy
Decision Points evaluate attested device posture, constrain AI agents, and
revoke sessions in near real time.

### Trust Is Inherited, Never Self-Asserted

The chain runs strictly upward from silicon to cloud because of one foundational
axiom: no software component can validly attest to its own integrity. A
compromised kernel asked whether its system-call table is clean will answer yes;
a forged bearer token whose signature verifies under a leaked key looks
cryptographically identical to an honest one. Trust must be *inherited* from a
lower layer placed outside the reach of the component being measured or
constrained.

Accordingly, the chapters ahead follow the exact sequence in which trust is
established. Part I (*Silicon*, [Chapter 1](16-secure-boot.md) through
[Chapter 5](04-attestation.md)) begins in firmware and hardware with UEFI Secure Boot,
the TPM, Microsoft Pluton, Measured Boot, and Remote Attestation. Part II
(*Kernel & Code*, [Chapter 6](05-secure-kernel.md) through [Chapter 9](19-mitigations.md))
traces the Secure Kernel and `VBS` trustlets, Code Integrity and Application
Control (`WDAC`), Protected Process Light (`PPL`), and Process Mitigation
Policies (`ACG`, `CFG`, and `CET`). Part III (*Credentials & Access*,
[Chapter 10](25-access-control.md) through [Chapter 17](12-hello.md)) examines how those
kernel boundaries protect tokens, `BitLocker` and `DPAPI` secrets, Credential
Guard, the retirement of `NTLM`, Kerberos and `krbtgt`, Enterprise PKI and
managed service accounts, Primary Refresh Tokens, and Windows Hello passkeys.
After an interlude on `ETW` and endpoint telemetry ([Chapter 18](28-etw.md)), Part IV
(*Cloud*, [Chapter 19](13-zero-trust.md) through [Chapter 22](29-confidential-vms.md))
extends verification across Zero Trust Conditional Access, Continuous Access
Evaluation, Workload and AI Agent Security, and hardware-encrypted Azure
Confidential VMs, culminating in [Chapter 23](15-storm0558.md)'s examination of
`Storm-0558`.

### Security Boundaries vs. Defense-in-Depth

Precision requires distinguishing a serviced security boundary from an
operational defense-in-depth feature. Microsoft's *Security Servicing Criteria
for Windows* draws an explicit engineering contract between boundaries Microsoft
commits to defending with mandatory security updates (such as user mode to
kernel mode, VM guest to host, and `VTL0` to `VTL1`) and administrative
convenience divisions it does not service as boundaries (such as standard default
User Account Control elevation between processes of the same user). Confusing the
two leads architects to build critical controls atop walls the platform vendor
never promised to hold.

### Cryptographic Validity Is Not Authorization

Every single link in this book has failed in production, and almost never
because `AES`, `SHA-256`, `RSA`, or `ECDSA` was broken mathematically. Discrete
TPM buses were passively sniffed with logic analyzers ([Chapter 2](01-tpm.md)); validly
signed UEFI bootloaders (`BlackLotus`, [Chapter 1](16-secure-boot.md)) and validly signed
third-party drivers (`BYOVD`, [Chapter 7](06-code-integrity.md)) subverted Secure Boot and
`PPL`; `CloudAP` SSO derivations enabled `Pass-the-PRT` without extracting TPM
keys ([Chapter 16](11-pth-prt.md)); and a genuine 2016 Microsoft consumer signing key
forged enterprise Exchange Online tokens (`Storm-0558`, [Chapter 23](15-storm0558.md)).
Across every tier, *cryptographic validity proves provenance under a key, never
runtime safety or resource-scoped authorization.*

Every claim in the pages ahead is cited to primary technical documentation,
standards specifications, and security research (`[N]`), and every chapter
closes with live, non-destructive inspection commands so you can verify what
your own fleet is actually enforcing rather than what group policy intended.

The chain begins below the operating system, at the hardware reset vector.
