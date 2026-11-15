# Confidential VMs

## Overview

* **Role in the Chain:** Extends hardware-rooted isolation and attestation (`Chapters 2, 5, 6`) into public-cloud multi-tenant infrastructure, protecting guest VM DRAM, CPU registers, and boot state from the cloud provider's host hypervisor and management plane.
* **Core Security Invariant:** Private guest physical pages are encrypted inline by the CPU memory controller and bound to expected guest physical addresses via hardware integrity tables (AMD `SEV-SNP` Reverse Map Table `RMP` or Intel `TDX` Physical-Address-Metadata Table `PAMT` + Secure EPT), while Secure Key Release (`SKR`) releases HSM keys only after Microsoft Azure Attestation (`MAA`) verifies silicon-signed `SNP_REPORT` / `TD Quote` and `OpenHCL` `vTPM` measurements against `authorizationrules`.
* **Trusted Computing Base (TCB):** CPU silicon and firmware signing roots (`AMD-SP` + `VCEK` chain or signed `Intel TDX Module` in `SEAM` + `SGX`/`DCAP` Quoting Enclave), the in-boundary `OpenHCL` Rust paravisor (`VMPL0` or `L1 TD`), `MAA`, and Azure Key Vault / Managed HSM (`SKR`); the Azure Hyper-V host hypervisor is *excluded* from memory confidentiality and integrity.
* **Primary Failure Modes:** Pre-`SNP` nested-page ciphertext remapping (`SEVered`, `SEVurity`), cache-writeback fault injection (`CacheWarp` `CVE-2023-20592`), hypervisor-injected virtualization exceptions and interrupts (`WeSee` `CVE-2024-25742`, `Heckler` `CVE-2024-25743`/`25744`), physical `AMD-SP` voltage glitching (`One Glitch`), and `MAA` policies misplacing security predicates inside `issuancerules` instead of `authorizationrules` or pinning stale `TCB SVN` floors.
* **Handoff:** Completes Part IV (*Cloud*) by proving a cloud operator can be excluded from workload memory while keeping guest `VTL0`/`VTL1` `VBS` intact inside; hands the final systemic question, what happens when a cloud signing root above every hardware boundary fails, to [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md).

## Core Engineering Problem & Threat Model

Every chapter from Secure Boot ([Chapter 1](16-secure-boot.md)) through Continuous Access Evaluation ([Chapter 20](14-cae.md)) assumed that the physical server or workstation hosting Virtualization-Based Security (`VBS`, [Chapter 6](05-secure-kernel.md)) was either owned directly by the enterprise or operated by an unconditionally trusted infrastructure provider. When regulated workloads migrate onto multi-tenant public clouds, spanning genomic clean rooms, inter-bank anti-money-laundering analytics, sovereign key-signing services, and frontier AI model weights, that physical custody assumption inverts. Although BitLocker and storage-layer ciphers protect data at rest and TLS 1.3 protects data in transit, data in use inside guest DRAM remains exposed in plaintext to a compromised cloud host hypervisor, a privileged host management agent, or a coerced datacenter operator [752, 753].

Process-scoped user-mode enclaves, pioneered commercially by Intel Software Guard Extensions (`SGX`, 2015), proved that an inline CPU memory encryption engine could exclude a hostile operating system and hypervisor from an Enclave Page Cache (`EPC`, initially limited to roughly `96 MiB` of usable DRAM). Yet process enclaves failed to generalize to unmodified Windows Server applications: `EPC` oversubscription triggered steep paging performance cliffs, developers had to manually partition programs across narrow `ECALL` and `OCALL` marshaling interfaces (a burden that even library-OS research prototypes like Microsoft *Haven* could not fully erase), and shared-core microarchitectural transient-execution attacks (`Foreshadow`, `SgxPectre`, and `SGAxe`) repeatedly extracted enclave sealing and attestation keys [754, 755, 756, 757].

Expanding the Trusted Execution Environment (`TEE`) boundary from a constrained user-mode enclave to an entire Virtual Machine, championed by AMD memory-encryption architect David Kaplan in 2016 and coordinated across silicon and cloud vendors through the Confidential Computing Consortium in 2019 [758, 759, 760, 761], unlocked lift-and-shift compatibility for full guest operating systems, while immediately exposing a deeper cryptographic lesson: *memory encryption without hardware page-mapping integrity is broken*. Under first-generation AMD `SEV` (2016-2017, which encrypted VM pages under per-guest `AES-128` keys indexed by Address Space Identifier `ASID` and controlled by the guest page-table `C-bit` [762, 763]) and `SEV-ES` (2017, which encrypted saved CPU register state across `VMEXIT` transitions and routed explicit host I/O through an unencrypted Guest-Hypervisor Communication Block `GHCB` [764]), the untrusted host hypervisor still controlled Nested Page Tables (`NPT`). In 2018, Fraunhofer AISEC's `SEVered` attack remapped guest physical pages backing a virtual NIC buffer onto encrypted secret pages so the guest OS obligingly decrypted and transmitted its own RAM over the network [765]. Subsequent breaks including `ICUP` (2019, `AMD-SP` firmware rollback [766]) and `SEVurity` (2020, exploiting `XEX` cipher malleability as an arbitrary guest code-injection oracle [767]) proved that production Confidential VMs require both a silicon-enforced page-ownership rail and `IETF RFC 9334` (`RATS`) remote attestation [768].

## Architectural Deep Dive

### Generation-2 Silicon: AMD `SEV-SNP` vs. Intel `TDX`

Published eight months apart in 2020, AMD `SEV-SNP` (*Secure Nested Paging*, introduced on 3rd Gen `EPYC 7003` Milan processors [769, 770, 771]) and Intel `TDX` (*Trust Domain Extensions*, introduced on 4th Gen Xeon Sapphire Rapids processors [772, 773, 774, 775]) strip guest-physical-to-host-physical (`GPA → HPA`) remapping power away from the cloud host hypervisor through two distinct silicon architectures. AMD enforces ownership inside hardware memory-controller lookup logic backed by an on-die ARM Secure Processor (`AMD-SP`), whereas Intel introduces a CPU-measured software arbiter (`Intel TDX Module`) running inside a dedicated x86 processor mode called Secure Arbitration Mode (`SEAM`), isolated within a reserved physical memory range (`SEAMRR`) and entered exclusively via `SEAMCALL` from the host VMM or `TDCALL` from the guest Trust Domain:

| Architectural Element | AMD `SEV-SNP` (`DCasv5`/`ECasv5`, `DCasv6`) | Intel `TDX` (`DCesv6`/`ECesv6`) |
|---|---|---|
| Inline Memory Cipher | Per-VM `AES-128` engine keyed by `ASID` (`C-bit` marks private pages) [762, 770] | Intel `TME-MK` (`AES-128-XTS` per Trust Domain `keyID`; GPA `Shared Bit` marks bounce buffers) [772, 776, 777] |
| Page-Mapping Integrity Rail | Reverse Map Table (`RMP`): System-wide table binding each `HPA` to `(ASID, expected GPA, VMPL ACL, validated bit)`; remaps raise `#NPF(rmpfault)` + guest `PVALIDATE` [769, 770] | Secure `EPT` + `PAMT` (Physical-Address-Metadata Table) managed exclusively inside `SEAM` [772, 774] |
| In-Silicon Mediator | On-die AMD Secure Processor (`AMD-SP`) + CPU microcode [770] | CPU-measured Intel `TDX Module` executing in Secure Arbitration Mode (`SEAM` / `SEAMRR`) via `SEAMCALL`/`TDCALL` [772, 774] |
| Intra-Guest Partitioning | 4-level `VMPL` lattice (`VMPL0` highest to `VMPL3` lowest) per `RMP` entry [770] | `TD` Partitioning (`L1 TD` paravisor hosting `L2 TD` guest) in `TDX Module 1.5` [774, 778] |
| Measurement Registers | Launch digest (`MEASUREMENT`) in `SNP_REPORT` (runtime PCRs held in `VMPL0` `vTPM`) [769, 770] | Launch `MRTD` + four runtime extendable registers `RTMR0-RTMR3` inside `TDX Module` [772, 773] |
| Hardware Quote & Root | `ECDSA-P384` `SNP_REPORT` signed by per-chip, per-TCB Versioned Chip Endorsement Key (`VCEK` → `ASK` → AMD Root) [769, 770] | `TDREPORT` (`TDCALL[TDG.MR.REPORT]`) signed by host `SGX` `TD` Quoting Enclave (`DCAP` / `PCK` → Intel Root) [772, 779] |

### The Azure Paravisor (`OpenHCL`), Synthesized `vTPM`, and Orthogonal `VMPL x VTL` Isolation

Unmodified Windows Server 2022/2025 lift-and-shift guests expect standard Hyper-V synthetic NICs, storage controllers, and a `TPM 2.0` (`Chapters 1-4`), none of which can safely run inside the untrusted host hypervisor [753, 780, 781]. Azure solves that compatibility gap by placing an open-source Rust paravisor, `OpenHCL` (built on `OpenVMM`, open-sourced October 2024; analogous to Linux `COCONUT-SVSM`), inside the encrypted CVM boundary at `VMPL0` (on `SEV-SNP`) or `L1 TD` (on `TDX`) [782, 783, 784, 785, 786].

![Figure: The full Azure confidential-VM stack, drawn across the confidentiality boundary. Below the line, AMD-SP / Intel TDX silicon roots the TCB and the Azure Hyper-V host is blind to encrypted RAM; above it, the OpenHCL paravisor and the VTL0/VTL1 Windows Server guest run inside the boundary. The right-hand rail is the attestation evidence flow: an SNP_REPORT or TD Quote plus a vTPM quote to MAA (policy v1.2), a signed JWT, then Key Vault / Managed HSM Secure Key Release. VMPL excludes the host; VTL excludes the guest kernel: the two orthogonal axes.](diagrams/29-confidential-vms-azure-stack.svg)

`OpenHCL` allocates explicit shared bounce buffers for untrusted host storage and network DMA while synthesizing a dedicated virtual TPM (`vTPM`) inside `VMPL0` (or `L1 TD`), unreachable from the customer guest OS running below it at `VMPL2` [753, 782]. As a result, a hardened Windows Server Confidential VM enforces two orthogonal hardware privilege lattices at the same time. Along the outer `VMPL` or `TD` partitioning axis, silicon page-ownership tables exclude the Azure Hyper-V host hypervisor and datacenter control plane from reading private guest DRAM or forging `OpenHCL`'s `vTPM` state [770, 782]. Along the inner `VTL0` / `VTL1` `VBS` axis ([Chapter 6](05-secure-kernel.md)), `OpenHCL` and Secure Kernel page protections exclude a compromised customer guest kernel in `VTL0` from dumping `LsaIso.exe` secrets (`Credential Guard`, [Chapter 12](08-credential-guard.md)) or injecting unsigned Ring 0 code past `HVCI` ([Chapter 7](06-code-integrity.md)) inside `VTL1` [753].

### `RATS` Passport Attestation, `MAA` Policy `v1.2`, `SKR`, and `H100` GPU Composition

Key custody in Azure Confidential VMs follows the `IETF RFC 9334` (`RATS`) Passport model [768]. During boot, `OpenHCL` requests a silicon-signed hardware report (`SNP_REPORT` under `VCEK` or `TD Quote` under Intel `DCAP`) whose `REPORT_DATA` field binds the paravisor's public attestation key alongside the launch digest of `OpenHCL` and UEFI firmware, and pairs that hardware quote with a `vTPM` quote covering Windows Secure Boot and Measured Boot `PCRs` (`PCR 7` and the `WBCL` event log) before submitting the combined evidence bundle to Microsoft Azure Attestation (`MAA`) [145, 753]. `MAA` evaluates the evidence against a customer-authored `version=1.2` policy structured across four blocks (`version`, `configurationrules` defaulting to `require_valid_aik_cert=true` and `required_pcr_mask=0xFFFFFF`, `authorizationrules`, and `issuancerules` using JmesPath claim transformations) and returns a signed JWT (`RFC 9711` `EAT` profile) that Azure Key Vault or Azure Managed HSM Secure Key Release (`SKR`) cryptographically validates before unwrapping OS-disk or workload encryption keys [145, 753, 787, 788].

Across commercial cloud platforms, whole-VM `SEV-SNP` and `TDX` instances on Azure and Google Cloud (`N2D` and `C3D` on `SEV-SNP` and `C3` on `TDX`, with live migration restricted to `Gen-1 SEV` because `SEV-SNP` and `TDX` deliberately block unauthenticated hypervisor state export [789, 790, 791]), together with pod-scoped Confidential Containers (`Azure Container Instances`, `AKS`, and `CNCF Confidential Containers` built on `Kata` and `Trustee` [792, 793, 794, 795, 796, 797, 798]), place the cloud host hypervisor outside the memory `TCB`. That threat boundary contrasts sharply with AWS Nitro Enclaves, which carve isolated CPU and unencrypted DRAM away from a *parent EC2 instance* under the mediation of AWS's Nitro Hypervisor, leaving AWS infrastructure firmware inside the memory `TCB` by design [799]. When workloads span confidential CPUs and accelerators (`Azure NCCadsH100v5` or `GCP A3`), relying parties must conjunctively verify (`AND`) both the host CPU `TEE` quote and NVIDIA `H100` Confidential Compute device attestation over a shared freshness nonce so model weights and inference prompts remain encrypted across PCIe bounce paths and GPU `HBM` [780, 790].

## Attack Catalog & Gap Analysis

The 2024 confidential-computing vulnerability wave demonstrated a critical structural truth: none of the modern attacks broke the `RMP` / `PAMT` page-mapping core; instead, every exploit targeted architectural seams surrounding the core [800, 801, 802, 803].

![Figure: The confidential-VM attack surface as concentric seams around the Generation-2 integrity rail. The RMP / PAMT core holds; each 2024-era attack lands in an outer seam: CacheWarp on the INVD cache-maintenance edge, WeSee on the #VC handler, Heckler on interrupt injection, and One Glitch as a physical fault beneath the AMD-SP, and none crosses into the core.](diagrams/29-confidential-vms-attack-rings.svg)

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `SEVered` & `SEVurity` | 2018 / 2020 | Gen-1 `SEV` / `SEV-ES` memory confidentiality & code integrity | Malicious host hypervisor on pre-`SNP` `EPYC` | Remaps `NPT` pages onto network I/O buffers (`SEVered`) or builds `XEX` cipher oracle (`SEVurity`) | Architecturally closed by `SEV-SNP` `RMP` (`#NPF(rmpfault)`) and `TDX` `PAMT` [765, 767, 770] |
| `ICUP` & `One Glitch to Rule Them All` (`PSPReverse`) | 2019 / 2021 | `AMD-SP` firmware / `VCEK` attestation root | Firmware downgrade (`ICUP`) or physical board voltage glitching (`Zen 1-3`) | Rolls back `AMD-SP` firmware or glitches `AMD-SP` boot ROM to extract chip endorsement secrets | Enforce `VCEK` `TCB SVN` floors (`ICUP`); datacenter physical security + newer silicon (`One Glitch`) [766, 804, 805] |
| `CacheWarp` (`CVE-2023-20592`, `AMD-SB-3005`) | 2024 | Guest writeback integrity on `SEV-ES` / `SEV-SNP` | Malicious hypervisor issuing `INVD` on unpatched microcode | Drops dirty guest CPU cache lines before DRAM writeback, reverting stack/auth variables (`sudo`/`sshd`/RSA) | Apply `AMD-SB-3005` microcode and raise `MAA` `authorizationrules` `tcb-svn` floor [803, 806, 807, 808] |
| `WeSee` (`Ahoi`, `CVE-2024-25742`) | 2024 | `SEV-SNP` guest kernel integrity & secret confidentiality | Malicious hypervisor injecting fake `#VC` (vector 29) | Spoofs `#VC` exceptions mid-instruction so guest `#VC` handler leaks registers/kTLS keys or executes root shells | Harden guest OS/paravisor `#VC` instruction-decoding validation (`SVSM`/`OpenHCL`/kernel fixes) [800, 801, 809] |
| `Heckler` (`Ahoi`, `CVE-2024-25743`, `CVE-2024-25744`) | 2024 | Both Intel `TDX` and AMD `SEV-SNP` control/data flow | Malicious hypervisor injecting `int 0x80` / signal vectors | Injects unexpected non-timer software interrupts altering register state in `OpenSSH`/`sudo`/analytics | Deploy guest kernel interrupt filtering, `SEV-SNP` Restricted Interrupt Injection, and `TDX` hardening [800, 802, 810, 811] |
| `MAA` `issuancerules` Misplacement & Unbound CPU+GPU Quotes | Persistent | Relying-party `SKR` secret gating | Hand-authored `MAA` policy or naive AI key-release service | Places `secureBootEnabled`/`tcb-svn` inside `issuancerules` (which never fail attestation!) or omits `H100` GPU quote check | Gate every invariant inside `authorizationrules` (`=> permit()`) and bind CPU + GPU nonces conjunctively [780, 788] |
| `Battering RAM` DDR Interposer (`IEEE S&P 2026`) | 2025-2026 | Deterministic `AES-XTS` TEE memory encryption | Physical motherboard access inserting ~$50 DDR4/DDR5 interposer | Switches address lines dynamically to alias/replay ciphertext across physical addresses against `SGX` / deterministic `XTS` engines [910] | Datacenter physical chassis security + cryptographic integrity/freshness trees or `RMP`/`PAMT` address binding [770, 910] |

### Why Notification and Cache Seams (`CacheWarp`, `WeSee`, `Heckler`) Bypass `RMP` and `PAMT`

Even when every DRAM cache line is encrypted and pinned in the `RMP` or `PAMT`, a virtual machine still depends on the untrusted host hypervisor to schedule vCPUs and deliver interrupts. CISPA's `CacheWarp` (`CVE-2023-20592`) abused CPU cache invalidation (`INVD`) to discard modified L1/L2 cache lines before they reached DRAM, turning a dropped store (`authenticated = 0` failing to overwrite `1`, or CRT-RSA fault math) into guest privilege escalation without touching nested page tables [803, 806]. Similarly, ETH Zurich's `Ahoi` attacks (`WeSee` `CVE-2024-25742` and `Heckler` `CVE-2024-25743`/`25744`) injected synthetic `#VC` or `int 0x80` exceptions that the guest kernel blindly processed as legitimate hardware traps [800, 809, 811]. Closing `CacheWarp` requires microcode (`AMD-SB-3005`) enforced via `TCB SVN` attestation floors [808]; closing `WeSee` and `Heckler` requires guest/paravisor exception-filtering hardening alongside hardware restricted-interrupt modes [809, 811].

## Theoretical Limits & Structural Invariants

### Irreducible Silicon Vendor Roots, Non-Reproducible Firmware, and Side Channels

Confidential VMs shrink and relocate the cloud trusted computing base into CPU silicon and attested paravisor code, yet never reduce that `TCB` to zero. Every workload running on `SEV-SNP` or `TDX` places unconditional cryptographic trust in AMD's proprietary `AMD-SP` firmware and `VCEK` PKI or in Intel's signed `TDX Module` and `SGX`/`DCAP` Quoting Enclave (audited in Google Project Zero's 2023 security review [812]). Neither silicon vendor currently publishes deterministic reproducible firmware builds anchored in public `Rekor`-style binary transparency logs, and both attestation roots rely on classical `ECDSA` and `RSA` signature chains awaiting future post-quantum (`ML-DSA` `FIPS 204`) hardware migration [769, 772, 812].

Microarchitectural side channels and physical motherboard interposers establish an equally hard outer perimeter. Neither `SEV-SNP` nor `TDX` hides ciphertext page-fault trajectories, cache-set contention timings, or encrypted I/O packet sizes from a host-resident observer, and logical CPU isolation cannot defeat laboratory voltage fault injection against older boot ROMs (`One Glitch` [804]). At IEEE S&P 2026, `Battering RAM` [910] further demonstrated that a low-cost (`~$50`) physical DDR4 memory interposer dynamically switching address lines defeats deterministic `AES-XTS` memory encryption engines (`Intel SGX` and static `XTS` modes lacking cryptographic address-freshness trees) by aliasing and replaying ciphertext blocks across physical addresses, confirming that datacenter chassis physical security and `RMP`/`PAMT` ownership checks serve as complementary layers rather than substitutes.

### Decoupling Hardware Memory Encryption from Relying-Party Key-Release Policy

Booting inside genuine `SEV-SNP` or `TDX` silicon protects nothing if the relying party releases keys without verifying launch measurements, `VBS` posture, and current `TCB SVN` floors inside `authorizationrules`.

> **Key idea.**
> Hardware memory encryption (`Rail 1`) stops a curious host from reading RAM directly, yet without strict remote attestation (`Rail 2`), an adversarial host can simply boot its *own* attacker-controlled Confidential VM on genuine AMD or Intel silicon, obtain a mathematically valid `VCEK` or `TD Quote` signature, and request the customer's secret from Key Vault. Workload confidentiality holds if and only if the `MAA` `v1.2` `authorizationrules` gate pins the expected `OpenHCL` and firmware launch measurement, `PCR 7` or `RTMR` Secure Boot baseline, `vbsEnabled == true`, and `tcb-svn >= latest_advisory` before emitting `permit()` [145, 788].

## Inspecting and Verifying on a Running System

Operational verification spans four checks: confirming Confidential VM SKU support, verifying that inner `VTL1` `VBS` (`Credential Guard` + `HVCI`) is active inside the guest, inspecting the `MAA` `v1.2` attestation policy structure, and validating issued `MAA` JWT claims.

### Verifying Regional `SEV-SNP` and `TDX` Confidential VM SKUs

Using Azure CLI, enumerate available `DCasv5`/`ECasv5` (`AMD SEV-SNP`) and `DCesv6`/`ECesv6` (`Intel TDX`) Confidential VM families in the target region [780]:

```bash
az vm list-skus --location eastus --resource-type virtualMachines \
    --query "[?contains(name, 'DCasv5') || contains(name, 'DCesv6')].[name, family]" -o table
```

### Confirming Orthogonal In-Guest `VBS` (`VTL1`) Isolation Inside the Windows CVM

Inside the running Windows Server Confidential VM, confirm that `VBS` (`VirtualizationBasedSecurityStatus = 2`) and `Credential Guard`/`HVCI` (`{1, 2}`) are actively isolating `VTL1` from `VTL0` inside the outer `VMPL`/`TD` boundary [753]:

```powershell
Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard |
    Select-Object VirtualizationBasedSecurityStatus, SecurityServicesConfigured, SecurityServicesRunning
Get-Tpm | Select-Object TpmPresent, TpmReady, ManufacturerIdTxt
```

Expected output inside an `OpenHCL`-backed Windows Server CVM:

```text
VirtualizationBasedSecurityStatus SecurityServicesConfigured SecurityServicesRunning
--------------------------------- -------------------------- -----------------------
                                2 {1, 2}                     {1, 2}
TpmPresent : True
TpmReady   : True
```

### Auditing `Microsoft Azure Attestation` (`MAA`) `v1.2` Policy Gates

Retrieve the active `SevSnpVm` (or `TdxVm`) attestation policy from your dedicated `MAA` provider and confirm that TEE type, launch measurement, `secureBootEnabled`, `vbsEnabled`, and `tcb-svn` floors live inside `authorizationrules` (which fail attestation on mismatch) rather than `issuancerules` [145, 788]:

```bash
az attestation policy show --name <maa-provider> --resource-group <rg> --attestation-type SevSnpVm \
    --query policy -o tsv | grep -E "version|authorizationrules|x-ms-sevsnpvm|tcb|permit"
```

Expected `authorizationrules` structure enforcing `TCB SVN` hygiene (`AMD-SB-3005`+):

```text
version=1.2;
authorizationrules { [type=="x-ms-attestation-type", value=="sevsnpvm"] && [type=="secureBootEnabled", value==true] && [type=="vbsEnabled", value==true] && [type=="x-ms-sevsnpvm-tcb-svn", value>=42] => permit(); };
```

## Summary & Handoff

Azure Confidential VMs complete the hardware-to-cloud architectural arc of Part IV: `AMD SEV-SNP` (`RMP`, `VMPL`, and `VCEK`) and `Intel TDX` (`SEAM`, `TDX Module`, `PAMT`, and `RTMR0-3`) strip guest DRAM visibility and page-remapping control away from the cloud host hypervisor, `OpenHCL` places an auditable Rust paravisor and synthesized `vTPM` inside `VMPL0` or `L1 TD` while preserving orthogonal `VTL0` / `VTL1` `VBS` inside the Windows Server guest, and `Microsoft Azure Attestation` gates `Secure Key Release` on `v1.2` `authorizationrules` enforcing up-to-date `TCB SVN` microcode floors against `CacheWarp`, `WeSee`, and `Heckler`.

Every defensive link of the chain now stands assembled, reaching from the `UEFI` reset vector and `TPM` / `Pluton` silicon up through `Secure Kernel` `VTL1`, `Code Integrity`, `PPL`, `Access Control`, `Credential Guard`, `Kerberos`, `PRT` brokers, `WebAuthn` passkeys, and `ETW`, and extending across the cloud through `Zero Trust`, `CAE`, `Entra Agent ID`, and `Confidential VMs`. In July 2023, not a single endpoint `TPM` failed, no `VTL1` trustlet was breached, Conditional Access evaluated policies normally, and `CAE` streams stayed green, yet a stolen consumer signing key honored by an incomplete enterprise validator forged cloud mail tokens across `22` organizations, including U.S. State Department diplomatic mailboxes. Dissecting how every individual link held intact while the chain itself snapped above them is the task of [When the Chain Snaps: Storm-0558 (Chapter 23)](15-storm0558.md).
