# Local Secret Custody: Kernel Keyrings, systemd-creds, and TPM2 PKCS#11

## Overview

* **Link in the Chain:** Secures service credentials, API secrets, and asymmetric private keys at rest and in RAM for sandboxed daemons ([Chapter 11](11-systemd-dbus-sandboxing.md)) and user sessions, binding secret availability to the `TPM 2.0` boot/PCR chain ([Chapter 2](02-uki-systemd-pcrlock.md)).
* **Core Security Invariant:** Long-lived secrets never reside in plaintext `/etc` files, swap-backed `tmpfs` mounts, or `/proc/<pid>/environ` strings; instead, `systemd-creds` seals service credentials via `AES-256-GCM` to `TPM 2.0` + host keys and projects them exclusively into non-swappable `ramfs` mounts (`/run/credentials/<unit>/`), while operational TLS/SSH keys execute inside `TPM 2.0` silicon (`tpm2-pkcs11`) or session-scoped (`@s`) kernel keyrings.
* **Deployment Profile Matrix:** Legacy mutable deployments scatter `0600` plaintext secrets across `/etc` and `.env` files; modern `systemd` (`v250+`) servers and immutable appliances (`CoreOS`, `Flatcar`, `UKI` hosts) seal declarative configs via `systemd-creds` (`LoadCredentialEncrypted=`) and `tpm2-pkcs11`; desktop workstations rely on `org.freedesktop.secrets` (`GNOME Keyring` / `KWallet`), requiring portal isolation to block D-Bus secret scraping.
* **Trusted Computing Base (TCB):** Linux `security/keys/` keyring subsystem (`trusted` and `encrypted` key types), `mm/secretmem.c` (`memfd_secret`), `TPM 2.0` Storage Root Key (`SRK`) and `PCR[7]`/`PCR[11]` policies, `systemd` (`PID 1` credential unsealer and `ramfs` mounter), and `tpm2-pkcs11` / `tpm2-tss`.
* **Integration Seam & Handoff:** Eliminates plaintext credential theft from disk images, backups, swap partitions, and sibling units; hands off authenticated human login (`PAM`, `SSSD`) and short-lived fleet SSH/FIDO2 identity to [Chapter 13](13-pam-ssh-fido2.md).

## Problem Statement & Threat Model

Contrast how Windows/macOS and traditional Linux handle application secrets. Windows provides the Data Protection API (`DPAPI`) and `CNG` TPM-backed key storage; Apple platforms provide the Secure Enclave-backed `Keychain` gated by code-signing entitlements. Historically, Linux had *neither* a universal userland secret vault *nor* hardware-bound service credential injection: daemons read plaintext private keys out of `/etc/ssl/private/server.key`, `/etc/wireguard/wg0.conf`, or `EnvironmentFile=/etc/sysconfig/myapp` protected solely by `0600` POSIX DAC permissions [101, 102]!

Trace every integration seam where `/etc` plaintext files and environment variables fail under realistic adversary models [102]:
First, *offline image, backup, and GitOps exposure*: in modern declarative infrastructure (`Ansible`, `NixOS`, `rpm-ostree`, golden VM AMIs, unencrypted `/etc` snapshots), baking a plaintext WireGuard key or database password into `/etc` leaks it to every backup archive and image registry! Second, *`DynamicUser=yes` incompatibility* ([Chapter 11](11-systemd-dbus-sandboxing.md)): if `/etc/myapp/db.key` is `0400 root:root`, an unprivileged `DynamicUser=yes` daemon (whose transient UID didn't even exist before start!) cannot open it without clumsy root wrapper scripts. Third, *swap and `/proc` leaks*: passing secrets via `Environment=API_KEY=...` exposes them inside `/proc/<pid>/environ`, `systemd` D-Bus unit property queries, crash dumps, and child sub-processes (a fatal mistake for AI coding agents in [Chapter 17](17-ai-agent-sandboxes.md)!), while staging decrypted keys onto standard `tmpfs` (`/run` or `/dev/shm`) allows the kernel page reclaimer under memory pressure to *write plaintext keys out to an unencrypted swap partition*! Fourth, *post-compromise key cloning*: even if a TLS client certificate key is decrypted safely into OpenSSL's userspace heap, an attacker who achieves memory read or `UID 0` copies the raw RSA/ECDSA private key bytes off the machine and impersonates the host from across the internet forever [103].

Closing these four failure modes requires matching each secret class to the right Linux custody primitive: Ring 0 non-swappable Kernel Keyrings (`keyctl` [101]) and `memfd_secret(2)` [106] for runtime kernel/session keys, `systemd-creds` (`LoadCredentialEncrypted=` [102]) for `TPM 2.0`-sealed service configuration injected via non-swappable `ramfs`, and `tpm2-pkcs11` [103] for non-exportable hardware-bound asymmetric keys.

## Kernel & Userspace Mechanics

### Kernel Keyrings (`add_key` / `keyctl`), Possession Semantics, and `memfd_secret`

Merged in Linux 2.6.10 (`security/keys/` [101]) originally to store NFSv4 Kerberos tickets, `dm-crypt` master keys, and `fs-verity`/`module` X.509 certificates inside non-swappable Ring 0 slab memory, the Linux Kernel Keyring facility exposes three system calls: `add_key(type, description, payload, plen, ring_id)`, `request_key(...)`, and the multiplexed `keyctl(cmd, ...)` interface [101]. Five special negative serial anchor IDs scope key lifetimes: `@t` (`KEY_SPEC_THREAD_KEYRING`), `@p` (`KEY_SPEC_PROCESS_KEYRING`), `@s` (`KEY_SPEC_SESSION_KEYRING`, inherited across `fork()` and `execve()` inside a login or `systemd` unit session when `KeyringMode=private` is set!), `@u` (`KEY_SPEC_USER_KEYRING`, shared globally across *every* process belonging to that `kuid_t`!), and `@us` (`KEY_SPEC_USER_SESSION_KEYRING`) [101].

![Figure: The five Linux kernel keyring scopes (@t, @p, @s, @u, @us) and the 32-bit Possessor|User|Group|Other permission mask, showing why service secrets belong in isolated @s session keyrings rather than UID-wide @u user keyrings.](diagrams/12-kernel-keyring-scopes.svg)

Unlike normal Unix `rwxrwxrwx` (9-bit User/Group/Other) permissions, every kernel key carries a 32-bit hexadecimal permission mask split into four 8-bit octets: `Possessor | User | Group | Other` (`0xPP_UU_GG_OO`, over six capability bits: `View=0x01`, `Read=0x02`, `Write=0x04`, `Search=0x08`, `Link=0x10`, `Setattr=0x20`) [101]! What is a *Possessor*? A thread *possesses* key $K$ if and only if $K$ is reachable via a live `Search`-permitted path starting from that thread's own `@t`, `@p`, or `@s` keyrings [101]! Look at why that distinction is load-bearing: if a utility creates a secret key linked into its private `@s` session keyring with mask `0x3f010000` (`pos:all`, `user:view` *without* `user:read`!), then another compromised process running under the exact same `UID 1000` in a different session cannot call `keyctl_read()` to steal the secret, because it is not a *Possessor*! Conversely, developers who mistakenly pass `0x3f3f0000` (`user:all`) or link secrets into `@u` expose them to every process sharing that `UID` [101].

Beyond simple `user` byte blobs, the kernel provides three hardened key types [46, 101]: `logon` keys behave identically to `user` keys except `keyctl_read()` is *permanently forbidden* (`-EOPNOTSUPP`): once userspace loads a `dm-crypt` or `CIFS` key as `logon`, only Ring 0 subsystems can ever read its payload! `trusted` keys generate random keys *inside* the `TPM 2.0` (`TPM2_Create` under the Storage Root Key `SRK` with optional PCR policies), returning only a `TPM`-wrapped blob to userspace for disk storage so plaintext never leaves Ring 0 + TPM! And for ultra-sensitive userspace crypto buffers (such as OpenSSL/BoringSSL master keys), Linux `5.14+` provides `memfd_secret(0)` (`mm/secretmem.c` [106]): pages allocated into this anonymous file descriptor are `mlock`-equivalent (never swapped) *and completely unmapped from the kernel's own linear direct map* (`set_direct_map_invalid_noflush`), defeating both cold swap leaks and speculative/Ring-0 direct-map read gadgets!

### `systemd-creds`: `TPM2`+Host Sealed Service Credentials Over `ramfs`

To kill `/etc` plaintext files and `Environment=` leaks across all daemons uniformly, `systemd` (`v250+` [102]) introduced the *System and Service Credentials* architecture (`systemd-creds(1)`):

![Figure: End-to-end secret lifecycle in systemd-creds: sealing secrets to TPM 2.0 + host secret via AES-256-GCM, storing opaque .cred blobs in /etc/credstore.encrypted/, and projecting plaintext exclusively into per-unit non-swappable ramfs mounts.](diagrams/12-systemd-creds-tpm2-flow.svg)

During provisioning, an administrator runs `systemd-creds encrypt --name=db-password - /etc/credstore.encrypted/db-password.cred` [102]. Under the hood (`--with-key=auto` selecting `host+tpm2`), `systemd-creds` generates a 256-bit `Host Key` stored on the encrypted `/var/lib/systemd/credential.secret` volume *and* seals a random key inside `TPM 2.0` bound to `PCR[7]` (UEFI Secure Boot policy, plus optional `--tpm2-pcrs=7+11` or `pcrlock`), combines both halves via `SHA-256` KDF to derive an `AES-256-GCM` key, binds the credential logical name (`db-password`) and optional monotonic `notAfter` expiration timestamp inside the GCM Additional Authenticated Data (`AAD`) (so an attacker cannot rename `low-priv-token.cred` to `root-api-key.cred`!), and writes the resulting `.cred` file [102]. Combining `host+tpm2` achieves defense in depth: stealing the disk image off-host fails because the attacker lacks the physical `TPM 2.0` chip, while stealing the motherboard without unlocking `LUKS2` `/var` fails because the attacker lacks `/var/lib/systemd/credential.secret`!

When `myapp.service` declares `LoadCredentialEncrypted=db-password:/etc/credstore.encrypted/db-password.cred` alongside `DynamicUser=yes` and `KeyringMode=private`, `PID 1` performs all `TPM 2.0` unsealing and `AES-256-GCM` verification outside the service, mounts a tiny private `ramfs` instance (explicitly `ramfs`, *not* `tmpfs`, guaranteeing the kernel VM subsystem can *never* swap a single credential byte out to disk under memory pressure! [102]) at `/run/credentials/myapp.service/` inside the unit's private mount namespace, writes `db-password` (`0400`, owned by the transient `DynamicUser`), sets `$CREDENTIALS_DIRECTORY=/run/credentials/myapp.service`, and unmounts/zeros the `ramfs` on service stop! Sibling services, `/proc/<pid>/environ` readers, and disk backups see nothing. Even better, in Cloud and Confidential VM deployments ([Chapter 18](18-confidential-vms-svsm.md)), `systemd` automatically ingests credentials passed via `SMBIOS` Type 11 OEM strings, `QEMU` `fw_cfg`, or `UKI` `.cred` PE sections, unsealing them cleanly at boot without modifying the immutable `/usr` image [20, 102]!

### Non-Exportable Hardware Keys (`tpm2-pkcs11`) and Desktop Keyring Risks

Even `ramfs` holds decrypted key bytes inside host DRAM while the service runs. For high-value operational asymmetric identities: node mTLS client keys, SSH host/client keys, or local `DKMS` code-signing keys: `tpm2-pkcs11` [103] implements the OASIS `PKCS#11` (`Cryptoki`) C interface backed directly by `TPM 2.0` hardware (`libtpm2_pkcs11.so`). When `OpenSSL` (`pkcs11-provider`), `OpenSSH` (`ssh -I /usr/lib64/pkcs11/libtpm2_pkcs11.so`), or `strongSwan` generates a keypair inside a `tpm2-pkcs11` token, the TPM generates the RSA-2048 or ECDSA P-256 private scalar internally with `TPMA_OBJECT_FIXEDTPM = 1` and `TPMA_OBJECT_FIXEDPARENT = 1` [2, 103]: there is literally no TPM command in silicon capable of exporting the plaintext private key. Every TLS 1.3 `CertificateVerify` or SSH handshake passes only a 32-byte digest into `TPM2_Sign` over the `tcti` `/dev/tpmrm0` kernel resource manager; an attacker who dumps the entire memory of `nginx` or `sshd` obtains zero reusable private key material!

Contrast that hardware discipline with a ubiquitous workstation pitfall: the Freedesktop *Secret Service D-Bus API* (`org.freedesktop.secrets`, implemented by `gnome-keyring-daemon` and `KWallet` [104]). When a developer logs into a graphical Linux desktop, `pam_gnome_keyring.so` unlocks the user's `login.keyring` automatically using their login password. Because `org.freedesktop.secrets` historically authenticated D-Bus peers *only* by checking that `ucred.uid == session_uid` without per-application cryptographic identity, any unconfined `npm` postinstall script, malicious VS Code extension, or unsandboxed CLI tool running under `UID 1000` can issue two D-Bus calls (`OpenSession` + `SearchItems`) and dump every Chrome cookie encryption key, GitHub token, and Wi-Fi passphrase in `login.keyring` silently [104]! On Linux workstations, sensitive developer credentials belong in `FIDO2` hardware tokens ([Chapter 13](13-pam-ssh-fido2.md)), `TPM2`-backed `ssh-agent` PKCS#11 tokens, or `xdg-desktop-portal` `org.freedesktop.portal.Secret` per-Flatpak/Snap isolated secrets rather than an ambient unlocked D-Bus keyring.

## Distro, Immutable-OS, & Cloud Trade-Offs

Adopting `systemd-creds` and `KeyringMode=private` requires zero kernel patches on any modern distribution (`RHEL 9+`, `Ubuntu 22.04/24.04+`, `Debian 12+`, `Fedora`, `CoreOS`, `Arch`), though upstream third-party packages (`PostgreSQL`, `Redis`, `Prometheus`) must either read `$CREDENTIALS_DIRECTORY/<name>` natively or invoke `systemd-creds cat` in a tiny `ExecStart=` wrapper when legacy binaries expect config file paths [102]. On bare-metal servers with discrete `TPM 2.0` chips, remember that hardware `TPM2_Sign` throughput via `tpm2-pkcs11` tops out around $15$ to $40$ ECDSA signatures/sec: ideal for mTLS client connections, `SPIRE` node attestation ([Chapter 16](16-workload-identity-spiffe.md)), and `SSH` host keys, whereas high-rate public HTTPS termination (`10,000` handshakes/sec) uses short-lived RAM certificates (`SPIFFE` / `ACME`) attested by the TPM-rooted node key [103, 132].

## Seam Failures, CVEs, & Structural Bounds

Secret-custody failures span permissive keyring bitmasks, kernel keyring reference-count overflows, `tmpfs` swap leaks, and ambient desktop D-Bus secret scraping.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| Kernel Keyring Refcount Overflow (`CVE-2016-0728`) | 2016 | `security/keys/process_keys.c` | `join_session_keyring()` decrements `usage` on existing-keyring fast path | 32-bit `atomic_t` leak ($2^{32}$ calls) frees active `struct keyring` for Ring 0 UAF LPE | Migrate kernel refcounts to saturating `refcount_t` (pins at `UINT_MAX` instead of wrapping!) [51, 105] |
| Over-Permissive `@u` Keyring / `0x3f3f0000` Mask | 2018-2025 | Application `add_key()` misuse | Kernel keyring automatically isolates processes of the same `UID` | App sets `user:read` (`0x3f3f0000`) or links into `@u`, letting any sibling `UID 1000` exploit read `keyctl print` | Set `KeyringMode=private`, link to `@s`, and grant `read` strictly to `Possessor` (`0x3f010000`) [95, 101] |
| `Environment=` & `tmpfs` Swap Secret Exposure | Architectural | `systemd` `Environment=` & `/dev/shm` | RAM-backed `tmpfs` never touches persistent disk | `/proc/<pid>/environ` leaks env vars, and `tmpfs` pages swap out to unencrypted swap partitions under load | Deliver secrets via `LoadCredentialEncrypted=` on non-swappable `ramfs` or encrypt swap (`swap` random ephemeral `dm-crypt`) [102] |
| Desktop `org.freedesktop.secrets` Ambient Scraping | 2019-2025 | `gnome-keyring` / `KWallet` D-Bus bus | Unlocked login keyring is safe against local processes | Malicious `pip`/`npm` package calls `org.freedesktop.secrets` over session D-Bus to dump stored tokens | Confine untrusted apps (`Bubblewrap`/`Flatpak` blocking D-Bus socket) and store SSH/OIDC keys in `FIDO2`/`TPM2` [103, 104, 136] |

Having secured how local services store and consume secrets on a single host, [Chapter 13](13-pam-ssh-fido2.md) examines how human administrators and enterprise identity providers authenticate *into* fleets of Linux hosts: and how OpenSSH Certificates, `FIDO2` hardware keys, and OpenSSH 9.8's privilege-separation split harden the network perimeter.

## Inspecting on a Live Linux Host

Inspect your current thread, process, and session kernel keyrings (`@s`, `@u`) and verify their 32-bit `Possessor|User|Group|Other` hex permission masks:

```bash
keyctl show 2>/dev/null || cat /proc/keys 2>/dev/null | head -n 10
```

Verify whether `systemd-creds` detects usable `TPM 2.0` + host-key sealing support on the live system and perform an ephemeral RAM round-trip test without touching `/etc`:

```bash
systemd-creds has-tpm2 2>/dev/null; echo "exit=$?"
# Encrypting/decrypting with host+tpm2 requires root / run0
printf "test-secret" | systemd-creds encrypt --with-key=null --name=demo - - 2>/dev/null | systemd-creds decrypt --name=demo - - 2>/dev/null; echo
```

Confirm that active service credential mounts under `/run/credentials/` use non-swappable `ramfs` rather than swappable `tmpfs`:

```bash
mount | grep "/run/credentials" | head -n 10
```
