# Runtime Appraisal and Attestation: IMA, IPE, and Keylime

## Overview

* **Link in the Chain:** Completes Part I by turning passive storage integrity (`dm-verity` and `fs-verity` in [Chapter 3](03-luks2-verity.md)) into active kernel execution enforcement (`IMA-appraisal` / `EVM` and Linux 6.12+ `IPE` LSM) and cryptographic proof to off-host verifiers (`Keylime` + `IETF RATS`).
* **Core Security Invariant:** Locally, the kernel admits `execve()`, `mmap(PROT_EXEC)`, `mprotect(PROT_EXEC)`, and firmware/policy reads only when the backing file satisfies active `IMA-appraisal` signatures or `IPE` verity policy; remotely, a `Keylime` verifier grants workload trust only when a `TPM 2.0` Attestation Key bound to genuine Endorsement silicon signs a fresh nonce-bearing `TPM2_Quote` over `PCR[0..11]` and `PCR[10]` whose replayed TCG and `IMA` event logs match approved reference values.
* **Deployment Profile Matrix:** Regulated mutable servers (`RHEL`, `SUSE`, telecom/defense) deploy `IMA` measurement into `PCR[10]` + `Keylime` continuous monitoring (and selectively `IMA-appraisal` + `EVM`); modern immutable appliances (`Linux 6.12+`, Azure Linux / embedded / CoreOS-style builds) adopt `IPE` over `dm-verity` and `fs-verity`; confidential cloud pods pair `RATS` attestation with `Trustee` ([Chapter 19](19-confidential-containers.md)).
* **Trusted Computing Base (TCB):** Linux kernel `security/integrity/ima/`, `security/integrity/evm/`, and `security/ipe/` LSMs, `.ima` / `.evm` / `.secondary_trusted_keys` keyrings, `TPM 2.0` `PCR[10]` and restricted Attestation Key (`AK`), Rust `keylime_agent`, and off-box `Keylime` Registrar + Verifier + Reference Value database.
* **Integration Seam & Handoff:** Prevents unapproved files from being mapped executable and exposes tamper-evident boot/runtime evidence off-host; hands off protection of running Ring 0 memory, kernel modules, and `kexec` transitions to Part II ([Chapters 5](05-kernel-lockdown-modules.md) through [7](07-stacked-lsms-landlock.md)).

## Problem Statement & Threat Model

Suppose a Linux host boots through a Microsoft- and `SBAT`-verified `shim.efi` ([Chapter 1](01-uefi-shim-sbat.md)), authenticates a signed `Unified Kernel Image` into `PCR[11]` ([Chapter 2](02-uki-systemd-pcrlock.md)), and mounts `/usr` read-only over `dm-verity` ([Chapter 3](03-luks2-verity.md)). Two fundamental trust gaps still remain open the instant `PID 1` spawns multi-user services. First, real Linux machines always mount writable filesystems alongside `/usr`: `/var`, `/tmp`, `/run`, `/dev/shm`, and anonymous memory descriptors (`memfd_create(2)`). If a network-facing service suffers a command-injection flaw or compromised credentials, nothing in `dm-verity` prevents the attacker from writing a malicious ELF implant or Python shared object to `/dev/shm/payload.so` and calling `execve()` or `dlopen(..., RTLD_NOW)` (`mmap` with `PROT_EXEC`). Storage integrity proves `/usr/bin/python3` is authentic; it says nothing about whether `/dev/shm/payload.so` is *authorized to execute*.

Second, even when local kernel gates function properly, a remote orchestrator, Kubernetes control plane, or zero-trust relying party cannot simply take a Linux node's word over TLS that Secure Boot, `UKI`, and runtime code integrity are intact. A compromised host with a stolen TLS client key will happily report `"healthy": true` in software APIs [40, 41]. Under an adversary model where individual edge servers, telecom base stations, or bare-metal worker nodes may experience offline tampering, disabled Secure Boot, unauthorized package installations, or post-compromise binary execution, the platform needs two coupled capabilities: *local runtime appraisal* (refusing to execute or load any code artifact lacking cryptographic provenance) and *continuous remote attestation* (proving both boot-time `PCR[0..11]` and runtime `PCR[10]` execution history to an external verifier via hardware-rooted `TPM 2.0` quotes) [36, 38, 40, 41].

Historically, Linux tackled both problems inside a single subsystem, the `Integrity Measurement Architecture` (`IMA`, merged in Linux 2.6.30 from IBM Research [36, 37]) paired with the `Extended Verification Module` (`EVM`). Twenty years of deployment experience revealed sharp engineering trade-offs in `IMA`'s mutable-xattr and sequential-hashing design, directly motivating the Linux 6.12 `Integrity Policy Enforcement` (`IPE`) LSM [38, 39] for modern verity-backed systems alongside CNCF `Keylime` [41, 43] for scalable `IETF RATS` (`RFC 9334` [40]) remote attestation.

## Kernel & Userspace Mechanics

### `IMA` Measurement (`PCR[10]`), `IMA-Appraisal`, and `EVM` Metadata Binding

Inside `security/integrity/ima/`, `IMA` registers hooks on `bprm_check_security` (binary execution), `mmap_file` / `file_mprotect` (shared libraries and executable mappings), `kernel_read_file` (kernel modules, firmware blobs, `kexec` images, and policies), and optionally policy-matched `file_open` calls [36, 37]. `IMA` separates two orthogonal duties: *measurement* (`ima_policy=tcb`, recording what ran for remote verifiers without blocking execution) and *appraisal* (`ima_appraise=enforce`, locally blocking access with `-EACCES` if cryptographic verification fails) [37, 42].

When `IMA` measures a file for the first time (caching the result in an `iint` integrity inode cache keyed by inode and `i_version` until a write invalidates it), the kernel reads the entire file sequentially from start to EOF to compute $\text{digest}(F) = \operatorname{SHA-256}(F)$, formats a template entry (`ima-ng` storing `<algo>:<file_digest>` + `<file_path>`, or `ima-sig` appending the `security.ima` signature bytes [42]), appends the record to the kernel's in-memory measurement list (`/sys/kernel/security/ima/binary_runtime_measurements`), and extends `TPM 2.0` `PCR[10]` with the template hash:

$$H_{\text{entry}} = \operatorname{SHA-256}\!\left(d_{\text{ima-ng}}(F, \text{path})\right), \qquad \text{PCR}[10] \leftarrow \operatorname{SHA-256}\!\left(\text{PCR}[10] \;\parallel\; H_{\text{entry}}\right)$$

Notice two subtle corners of `IMA`'s measurement state machine [36, 37]. What if Process A opens a file `O_RDONLY` (triggering `IMA` measurement) while Process B simultaneously holds that same file open `O_RDWR` and mutates bytes in page cache after `IMA` hashed it? `IMA` detects this Time-of-Measure to Time-of-Use (`ToMToU`) conflict (and `open_writers` violations when a writer opens an already-measured file) by extending a special *all-zeroes* ($0^{256}$ / `0x00..00` mapped to `0xff..ff` inside TPM extend to prevent spoofed zero hashes) violation entry into `PCR[10]`, permanently tainting `PCR[10]` until reboot so a remote `Keylime` verifier knows the runtime log can no longer guarantee completeness [36, 41]!

When `IMA-appraisal` is active, the kernel verifies each matched file against an asymmetric RSA/ECDSA `ima-sig` digital signature (or `fs-verity` digest signature in `IMA` v3 format) stored in the file's `security.ima` extended attribute against the `.ima` trusted keyring [37, 42]. Yet on a mutable filesystem, `security.ima` only covers file *contents*, not file *permissions* or *labels*: an offline attacker could transplant a valid `security.ima` xattr onto a `SUID-root` inode or strip `security.selinux` labels. The `Extended Verification Module` (`EVM`, `security/integrity/evm/`) closes metadata tampering by maintaining `security.evm`, either an asymmetric vendor signature (for immutable vendor files) or an `HMAC-SHA256` keyed by a `TPM 2.0`-sealed kernel master key covering the tuple `(i_ino, i_generation, i_uid, i_gid, i_mode, security.ima, security.selinux, security.SMACK64, security.capability)` [37].

### Linux 6.12+ Integrity Policy Enforcement (`IPE`) LSM

Why did hyperscale cloud platforms, container hosts, and immutable appliance builders struggle to deploy `IMA-appraisal` + `EVM` in production? Maintaining per-file `security.ima` and `security.evm` extended attributes across millions of files during `rpm`/`deb` upgrades is notoriously brittle (`tar`, `rsync`, and older OCI image unpackers routinely strip or desynchronize `security.evm` `i_ino` bindings), hashing multi-hundred-megabyte binaries linearly from start to finish on first `execve()` stalls startup and offers zero protection if underlying storage blocks flip *after* open, and `IMA`'s low-level policy language lacks native first-class predicates for block-level `dm-verity` root provenance [38, 39].

![Figure: Architectural comparison between legacy IMA-Appraisal + EVM (per-file xattrs, whole-file linear hashing, and ToMToU hazards) and the Linux 6.12+ Integrity Policy Enforcement (IPE) LSM evaluating demand-paged dm-verity and fs-verity Merkle roots.](diagrams/04-ima-vs-ipe-enforcement.svg)

Merged in Linux 6.12 by Microsoft Linux engineers Fan Wu and Deven Bowers [38, 39], the `Integrity Policy Enforcement` (`IPE`) LSM (`security/ipe/`) solves code integrity cleanly by delegating cryptographic hashing entirely to the demand-paged Merkle trees already built into the kernel (`dm-verity` and `fs-verity` from [Chapter 3](03-luks2-verity.md))! `IPE` hooks five exact execution and kernel-data vectors: `bprm_check_security` (`execve`), `mmap_file` and `file_mprotect` (blocking `PROT_EXEC` mappings on anonymous or writable files unless permitted, while allowing JIT compilers only where policy explicitly scopes), `kernel_read_file`, and `kernel_load_data` (firmware, kernel modules, `kexec` images, and security policies) [38]. Instead of reading files linearly or parsing xattrs, `IPE` inspects O(1) kernel struct state (`bdev` `dm-verity` root digest/signature status or `inode` `fsverity_info` digest/signature status) against a human-readable, auditable policy exposed under `/sys/kernel/security/ipe/policies/`:

```text
policy_name="immutable_node" policy_version=1.0.0
default_action=DENY

op=EXECUTE boot_verified=TRUE action=ALLOW
op=EXECUTE dmverity_signature=TRUE action=ALLOW
op=EXECUTE fsverity_signature=TRUE action=ALLOW
op=KMODULE boot_verified=TRUE action=ALLOW
```

Look at what those six lines achieve with zero extended-attribute maintenance [38]: `boot_verified=TRUE` permits execution from the `initramfs` embedded inside our verified `UKI`; `dmverity_signature=TRUE` (or `dmverity_roothash=<sha256>`) permits execution from the read-only `dm-verity` `/usr` partition and signed `systemd-sysext` overlays; `fsverity_signature=TRUE` permits execution of explicitly signed `fs-verity` packages on writable partitions; and `default_action=DENY` deterministically blocks every attempt to execute binaries or `dlopen()` shared objects dropped into `/tmp`, `/var`, `/dev/shm`, or home directories! Because `dm-verity` and `fs-verity` verify every individual $4\text{ KiB}$ page fault in $O(\log N)$ hashes, post-open disk tampering and `ToMToU` races vanish structurally, while runtime policy updates pushed to `/sys/kernel/security/ipe/new_policy` must carry a valid PKCS#7 signature chaining to `.secondary_trusted_keys` with a strictly non-decreasing `policy_version` [38].

### Continuous Remote Attestation with `Keylime` and `IETF RATS`

Local enforcement (`IPE` or `IMA-appraisal`) stops an unverified binary from running on a well-behaved kernel, yet cannot prove to an external peer that an edge server did not reboot with `SecureBoot` turned off in BIOS setup or boot an unhardened kernel. Standardized in `RFC 9334` (*Remote ATtestation procedureS*, `RATS` [40]) and implemented for Linux fleets by CNCF `Keylime` (featuring a memory-safe Rust `keylime_agent` on the monitored node [41, 43]), continuous remote attestation separates four distinct roles: the *Attester* (the Linux host + `TPM 2.0`), the *Verifier* (`keylime_verifier`), the *Reference Value Provider* (supplying golden `UKI` `PCR[11]` digests, UEFI `PCR[0..7]` baselines, and signed `IMA` file allowlists/runtime policies), and the *Relying Party* (the SDN controller, service mesh, or secret vault consuming the Verifier's attestation verdict) [40, 41].

![Figure: Continuous remote attestation protocol in CNCF Keylime mapped onto IETF RATS (RFC 9334), binding a restricted TPM 2.0 Attestation Key to hardware Endorsement silicon via MakeCredential/ActivateCredential before polling nonce-fresh PCR[0..11] + IMA PCR[10] quotes.](diagrams/04-keylime-rats-attestation.svg)

How does the `Keylime` Registrar know it is talking to a genuine hardware `TPM 2.0` rather than a software emulator running on an attacker's laptop? Every discrete or firmware `TPM 2.0` ships with an Endorsement Key (`EK`) derived from the immutable Endorsement Primary Seed (`EPS`) and certified by an X.509 manufacturer certificate (`Infineon`, `Nuvoton`, `STMicroelectronics`, `Intel`, `AMD`) [2, 41]. Because the `EK` is a decryption-only storage key (and reusing one static signing key across verifiers creates privacy correlation), `keylime_agent` generates a restricted signing *Attestation Key* (`AK`, carrying object attribute `TPMA_OBJECT_RESTRICTED = 1` so the TPM refuses to sign any arbitrary external hash that lacks the internal `TPM_GENERATED_VALUE` `0xff544347` magic header!) [2, 41]. The Registrar validates the `EK` manufacturer X.509 chain, generates a random activation secret, and wraps it via `TPM2_MakeCredential` encrypted to $PK_{\text{EK}}$ *and* cryptographically bound to $\operatorname{Name}(PK_{\text{AK}})$. Inside silicon, `TPM2_ActivateCredential` releases the secret if and only if the exact restricted `AK` is loaded inside the *same* TPM that holds $SK_{\text{EK}}$ [2, 41].

Once enrolled, the `Keylime` Verifier continuously polls the agent (for example every $2$ to $10$ seconds) with a fresh 128-bit cryptographic nonce $n$ [41]. The TPM executes `TPM2_Quote`, signing `TPMS_ATTEST` (containing $n$, monotonic clock/reset counters, and the aggregate digest over `PCR[0..11]`, including `PCR[10]`) with $SK_{\text{AK}}$, while `keylime_agent` streams only the *new* byte offset delta of `/sys/kernel/security/ima/ascii_runtime_measurements` appended since the previous poll [41]. The Verifier checks the `AK` signature and nonce freshness, replays the incremental `IMA` hashes sequentially to confirm the simulated `PCR[10]` matches the hardware-signed `TPM2_Quote` digest bit-for-bit, verifies every executed file digest against the Reference Value allowlist (rejecting any `ToMToU` $0^{256}$ violation entries), and fires instant revocation webhooks (revoking mTLS certificates via `SPIRE`, draining Kubernetes nodes, or isolating switch ports) within seconds of an unauthorized binary or script execution [41, 43].

## Distro, Immutable-OS, & Cloud Trade-Offs

Combining `IMA` measurement + `Keylime` vs. `IPE` enforcement reflects a sharp operational divide. On mutable enterprise Linux hosts (`RHEL 9/10`, `Ubuntu Server`) where administrators still apply `dnf`/`apt` RPM/DEB updates and run interpreted Python or shell scripts (`ima_policy=tcb` plus `BPRM_CHECK` on scripts), `IMA` *measurement* paired with `Keylime` reference allowlists grown automatically from signed RPM/DPKG repo metadata provides strong post-compromise detection without fragile `security.evm` xattr lockouts, although high-churn container nodes require careful `IMA` policy scoping (`dont_measure` on ephemeral container overlay log mounts) to keep `PCR[10]` log growth bounded [37, 41]. Conversely, on modern Linux `6.12+` immutable nodes where `/usr` is `dm-verity` and packages use `fs-verity`, `IPE` enforces deterministic preventative blocking in Ring 0 with near-zero memory and CPU overhead, pairing cleanly with `TPM 2.0` boot attestation (`PCR[0..13]`) without needing millions of per-file `PCR[10]` events [38, 39].

## Seam Failures, CVEs, & Structural Bounds

Runtime appraisal and remote attestation encounter sharp structural limits around interpreted languages, memory-only payloads, `PCR[10]` log saturation, and the Time-of-Attest to Time-of-Compromise window.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| Interpreted Script stdin / `-c` Bypass | 2015-2025 | `IMA` / `IPE` `bprm_check_security` | Blocking unsigned ELF binaries prevents arbitrary code execution | Attacker pipes payload into signed `/usr/bin/python3 -c "..."` or `bash < socket`; `execve` sees only valid signed interpreter! | Omit general-purpose interpreters on immutable appliances (`Talos`/`Distroless`) or enable Python `PEP 578` audit hooks / `AT_EXECVE_CHECK` (`Linux 6.14+`) [34, 38] |
| `IMA` `ToMToU` / `mmap` Shared-Write Bypass | 2018-2023 | `IMA-appraisal` on mutable `ext4` | Sequential hash at `open()` stays valid throughout process lifetime | Writable mapping mutates file pages after `IMA` check or abuses filesystem caching edge cases | Enforce `IPE` over immutable `dm-verity` / `fs-verity` Merkle trees where writes are impossible [33, 38] |
| `EVM` Offline Metadata Transplant (Without TPM HMAC) | 2019-2022 | `IMA-appraisal` deployed without `EVM` | `security.ima` xattr signature protects `chmod +s` / `UID` bits | Offline attacker copies valid signed binary and sets `SUID-root` mode bit on mutable disk | Enable `TPM2`-backed `EVM` HMAC or mount non-verity volumes `nosuid,noexec` [37] |
| `PCR[10]` Event-Log Carry-Over / Replay (`kexec` Seam) | 2021-2023 | `IMA` across `kexec_file_load` soft reboot | Soft-rebooted kernel starts with clean `IMA` log matching `PCR[10]` | Hardware `PCR[10]` retains pre-`kexec` state; without `CONFIG_IMA_KEXEC` buffer handoff, `Keylime` replay fails or misaligns | Enable `CONFIG_IMA_KEXEC` log serialization and attest `kexec` events explicitly [41, 47] |
| Attestation Check-to-Compromise Window | Architectural | `TPM2_Quote` / `RATS` (`RFC 9334`) | Valid `TPM2_Quote` at $t_0$ proves host integrity at $t_0 + \Delta t$ | Ring 0 memory exploit corrupts kernel heap *after* binary loads without executing new files (`PCR[10]` unchanged!) | Pair attestation with `Kernel Lockdown`, `KCFI`, Shadow Stacks, and Rust memory safety (Part II) [40, 44, 53] |

Row 1 and Row 5 state two permanent theoretical bounds of *all* file-level integrity architectures [38, 40]. First, *the interpreter equivalence bound*: `execve()` and `mmap(PROT_EXEC)` mediate machine-code loading, not data streams interpreted by Turing-complete runtimes (`bash`, `python3`, `node`, `perl`). Unless interpreters themselves query kernel integrity on scripts via the `execveat(..., AT_EXECVE_CHECK)` flag introduced in Linux `6.14` (and wired into `IPE`/`IMA`) or are omitted entirely from production appliance images, living-off-the-land script execution bypasses binary allowlists. Second, *load-time measurement is not runtime memory safety*: `IMA`, `IPE`, and `Keylime` prove that only authentic binaries entered memory, yet if an authentic kernel driver or network daemon contains a Use-After-Free vulnerability, an attacker hijacks Ring 0 in RAM without ever touching disk or extending `PCR[10]`. Protecting the running kernel itself against `UID 0` and memory corruption is the task of Part II ([Chapters 5](05-kernel-lockdown-modules.md) through [7](07-stacked-lsms-landlock.md)).

## Inspecting on a Live Linux Host

Check whether `IMA`, `EVM`, and `IPE` are compiled and active in the running kernel's stacked LSM list and inspect the `IMA` runtime measurement count:

```bash
cat /sys/kernel/security/lsm 2>/dev/null; echo
# Reading securityfs IMA/IPE policy and logs typically requires root / run0
wc -l /sys/kernel/security/ima/ascii_runtime_measurements 2>/dev/null
head -n 5 /sys/kernel/security/ima/ascii_runtime_measurements 2>/dev/null
```

Inspect active `IMA` policy rules and check `EVM` initialization bitmask (`0x1` = HMAC initialized, `0x2` = public-key x509 loaded):

```bash
cat /sys/kernel/security/ima/policy 2>/dev/null | head -n 15
cat /sys/kernel/security/evm 2>/dev/null
```

On Linux `6.12+` kernels built with `CONFIG_SECURITY_IPE=y`, list loaded `IPE` policies and determine which policy is currently active:

```bash
ls -la /sys/kernel/security/ipe/policies/ 2>/dev/null
cat /sys/kernel/security/ipe/active_policy 2>/dev/null
```

Verify `TPM 2.0` `PCR[10]` bank state alongside any running `Keylime` agent unit:

```bash
tpm2_pcrread sha256:10 2>/dev/null || systemd-analyze pcrs 10 2>/dev/null
systemctl is-active keylime_agent.service 2>/dev/null || true
```
