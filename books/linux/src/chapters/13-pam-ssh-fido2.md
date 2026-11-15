# PAM, Hybrid Enterprise Identity, OpenSSH Certificates, and regreSSHion

## Overview

* **Link in the Chain:** Closes Part III by governing human and administrative entry into Linux hosts across local consoles and remote networks (`PAM`, `SSSD` Kerberos/AD/OIDC, OpenSSH Certificates, `FIDO2` hardware authenticators, and `sshd` privilege separation).
* **Core Security Invariant:** Host entry succeeds only when ordered `PAM` `auth` and `account` stacks both pass without `sufficient` bypasses, `SSSD` cryptographically validates KDC/OIDC tokens against host keytabs or JWKS roots, and `sshd` verifies short-lived CA-signed User Certificates paired with hardware-resident `FIDO2` (`sk-ssh-ed25519@openssh.com` `verify-required`) assertions inside a per-connection `ASLR`-randomized `sshd-session` process.
* **Deployment Profile Matrix:** Enterprise mutable fleets (`RHEL`, `Ubuntu`, `SUSE`) integrate `PAM` + `SSSD` (`FreeIPA`, Active Directory, or Entra ID OIDC) with CA-signed OpenSSH certificates; immutable container OSes (`Talos` omits `sshd`/`PAM` completely; `Bottlerocket` isolates admin SSH inside a separate host container; `CoreOS` uses `sshd` key/cert only with password auth disabled).
* **Trusted Computing Base (TCB):** Pre-auth `sshd` and `sshd-session` binaries, `TrustedUserCAKeys` offline/HSM SSH CA, `CTAP2`/`FIDO2` security key firmware, `libpam` + configured `/etc/pam.d/*` `.so` modules, and `SSSD` responder/backend processes.
* **Integration Seam & Handoff:** Authenticates human operators without static `~/.ssh/authorized_keys` sprawl or harvestable disk keys, and isolates pre-authentication `sshd` network parsing from `glibc` signal races (`regreSSHion`); hands off machine-to-machine container, AI sandbox, and `SPIFFE` cloud workload isolation to Part IV ([Chapter 14](14-containers-escapes.md)).

## Problem Statement & Threat Model

Every Linux fleet eventually confronts an operational and security crisis at its administrative perimeter [109, 110, 111]. In small deployments, engineers paste raw `ssh-ed25519` public keys into `~/.ssh/authorized_keys` across dozens of servers, click `yes` on Trust-On-First-Use (`TOFU`) host-key warnings (`The authenticity of host ... can't be established`), enable `ForwardAgent yes` so jump hosts can reach internal subnets, and leave unencrypted `~/.ssh/id_ed25519` private keys sitting on developer laptops. Scale that pattern to five thousand cloud instances and two hundred engineers, and four structural failures emerge simultaneously [109, 110, 112]:

First, *static key immortality and revocation blindness*: when an engineer leaves the company or a laptop is compromised, stale `authorized_keys` entries linger on forgotten bastions and snapshots forever because raw SSH keys carry no expiration timestamp (`notAfter`) and no central revocation feed; meanwhile, `TOFU` trains users to ignore Man-in-the-Middle (`MITM`) alerts whenever cloud auto-scaling recycles an IP address [109]. Second, *private-key exfiltration and `ssh-agent` hijacking*: any malware or prompt-injected coding agent ([Chapter 17](17-ai-agent-sandboxes.md)) running on the engineer's laptop copies `~/.ssh/id_ed25519` (or hijacks `$SSH_AUTH_SOCK`), while `ForwardAgent yes` exposes the engineer's live signing socket (`/tmp/ssh-XXXX/agent.<pid>`) to anyone holding `UID 0` on an intermediate jump box: compounded by `CVE-2023-38408` [112], where a malicious jump host abused forwarded PKCS#11 requests to `dlopen()` arbitrary shared libraries on the *engineer's own workstation*! Third, *`PAM` and hybrid directory complexity*: bridging Linux servers into enterprise Active Directory or cloud OIDC (`Entra ID`, `Okta`) introduces subtle `PAM` stack ordering traps where a single misplaced `sufficient` keyword grants login to disabled accounts [107, 108]. Fourth, *pre-authentication `sshd` network exposure*: because TCP port `22` often faces hostile networks directly, any memory-corruption bug in `sshd` prior to user authentication: exemplified by July 2024's `regreSSHion` (`CVE-2024-6387`) [111]: threatens unauthenticated remote root takeover before `PAM`, `SELinux`, or `FIDO2` ever run!

## Kernel & Userspace Mechanics

### `Linux-PAM` Stack Semantics and `SSSD` Hybrid Enterprise Identity

Whenever `login`, `sshd` (`UsePAM yes`), `polkitd`, or `systemd --user` authenticates or initializes a session, `libpam` evaluates a per-service configuration file in `/etc/pam.d/<service>` across four independent management groups [107]: `auth` (verifying *who* the user claims to be via password, Kerberos, OIDC device flow, or FIDO2 `pam_u2f.so`), `account` (verifying *whether* that authenticated identity is currently permitted access: account expiration, time/host access control `HBAC`, `/etc/nologin`, `pam_faillock`), `session` (setting up and tearing down runtime state: `pam_systemd.so` registering the `systemd-logind` session scope + `cgroup`, `pam_limits.so`, `pam_keyinit.so` initializing a fresh `@s` kernel keyring from [Chapter 12](12-keyrings-systemd-creds.md)!), and `password` (updating credentials) [107].

Inside each group, module ordering and control flags (`requisite`, `required`, `sufficient`, `optional`, or explicit bracket syntax `[success=done new_authtok_reqd=done default=ignore]`) form a state machine where order is security-critical [107]: `requisite` aborts the stack *immediately* on failure; `required` records failure but continues running remaining modules so attackers learn no timing oracle about which check failed; and `sufficient` returns immediate overall success the instant it passes (provided no *prior* `required` module failed!), skipping every module below it in that group! Placing `auth sufficient pam_sss.so` *above* `auth required pam_faillock.so preauth` or omitting `account required pam_sss.so` when `sshd` authenticates via SSH keys (`UsePAM yes` skips PAM `auth` on public-key login and runs *only* PAM `account` + `session`!) allows locked-out or terminated employees to keep logging in via SSH keys unless directory revocation lives in the `account` stack [107, 108]!

To avoid linking heavyweight LDAP, Kerberos, and HTTP/TLS libraries directly into privileged `PID 1` or `sshd` processes, enterprise Linux isolates network identity inside the System Security Services Daemon (`SSSD`) [108]. Thin unprivileged NSS (`libnss_sss.so.2`) and PAM (`pam_sss.so`) client stubs talk over local UNIX sockets to `sssd_nss` and `sssd_pam` responders, which dispatch to domain backends (`sssd_be` for Active Directory / `FreeIPA` / LDAP+Kerberos, or `oidc_child` / `Himmelblau` for OAuth 2.0 / OIDC Entra ID and Okta federation) [108]. Crucially, when `SSSD` validates a Kerberos password against an Active Directory Domain Controller (`AS-REQ` / `AS-REP`), an attacker spoofing DNS/KDC traffic on the LAN could forge a fake `AS-REP` encrypted to the user's password unless `SSSD` enforces `krb5_validate = true` (default in `id_provider = ad`/`ipa`): `SSSD` additionally requests a service ticket (`TGS-REQ`) for the Linux host's own restricted `/etc/krb5.keytab` principal (`host/node01.corp.example@CORP.EXAMPLE`) and decrypts it locally, mathematically proving that the KDC shares the domain secret [108]!

### Short-Lived OpenSSH Certificates and `FIDO2` (`sk-ssh-ed25519@openssh.com`)

Rather than importing bloated ASN.1/X.509 parsers into `sshd` (after watching decades of OpenSSL X.509 CVEs), Damien Miller and the OpenBSD OpenSSH team designed a compact, deterministic, length-prefixed binary certificate format (`PROTOCOL.certkeys` [109], types `ssh-ed25519-cert-v01@openssh.com` and `sk-ssh-ed25519-cert-v01@openssh.com`):

![Figure: Zero-TOFU, zero-authorized_keys fleet SSH architecture combining OIDC-issued short-lived OpenSSH User/Host Certificates with non-exportable FIDO2 hardware keys (sk-ssh-ed25519@openssh.com with verify-required).](diagrams/13-openssh-certs-fido2-handshake.svg)

Look at how clean and complete this mutual-CA handshake is [109, 110]:
First, *Host Certificates kill `TOFU`*: every Linux host signs its `/etc/ssh/ssh_host_ed25519_key.pub` under an internal Host CA (`ssh-keygen -s host_ca -I node01 -h -n node01.prod.internal -V +52w`), while engineer workstations carry a single static line in `/etc/ssh/ssh_known_hosts`: `@cert-authority *.prod.internal ssh-ed25519 AAAAC3...`! Every newly autoscaled server authenticates cryptographically on first connection with zero interactive `yes/no` prompts.
Second, *Short-Lived User Certificates kill `authorized_keys` sprawl*: servers configure `TrustedUserCAKeys /etc/ssh/user_ca.pub` and `AuthorizedKeysFile none` inside `sshd_config`. At the start of a shift, the engineer authenticates to an SSO-integrated SSH CA (`step-ca`, `HashiCorp Vault`, `Teleport`, `Cloudflare`) via enterprise OIDC + WebAuthn MFA and receives a User Certificate valid for strictly 8 hours (`valid_after`..`valid_before`), scoped to explicit `principals` (mapped via `AuthorizedPrincipalsFile`) and optional critical options (`source-address`, `force-command`, `no-agent-forwarding`) [109]. When the 8-hour window expires, access terminates globally across 50,000 hosts with zero CRL distribution!

Third, pairing OpenSSH Certificates with `FIDO2` (`CTAP2`) hardware security keys (`sk-ssh-ed25519@openssh.com` [110]) kills private-key theft! Generated via `ssh-keygen -t ed25519-sk -O resident -O verify-required`, the private key never exists on the laptop's SSD: `~/.ssh/id_ed25519_sk` contains only an encrypted `CTAP2` key handle wrapped by a secret inside the hardware YubiKey/SoloKey (or with `-O resident`, stays inside the token's NVRAM entirely!). On every SSH login, `sshd` computes the unique session exchange hash $H$, and the hardware token signs:

$$M_{\text{FIDO2}} = \operatorname{SHA-256}(\texttt{"ssh:"}) \;\parallel\; \text{flags}_{1\text{B}} \;\parallel\; \text{counter}_{4\text{B}} \;\parallel\; \operatorname{SHA-256}(H)$$

Where bit `0x01` of `flags` attests physical capacitive touch (*User Presence*, blocking silent background agent abuse!) and bit `0x04` attests on-device PIN or biometric verification (*User Verification*) [110]! Setting `PubkeyAuthOptions verify-required` inside `sshd_config` causes `sshd` itself to cryptographically verify bit `0x04` inside the signed `M_FIDO2` blob, guaranteeing that even if an attacker gains root on the engineer's laptop, they cannot forge a single SSH connection without physical touch + PIN on the hardware key (and with `ProxyJump -J bastion target` replacing `ForwardAgent yes`, no agent socket is ever exposed on intermediate jump hosts [112])!

### `regreSSHion` (`CVE-2024-6387`) and OpenSSH 9.8's Privilege-Separation Split

Even with password login disabled and `TrustedUserCAKeys` + `FIDO2` enforced, the pre-authentication parser of `sshd` faces unauthenticated TCP clients directly. Since OpenSSH 3.2 (2002), `sshd` pioneered *Privilege Separation* (`privsep`): the root listener forked a privileged *monitor* child per connection, which in turn forked an unprivileged `sshd: [net]` network child (`UID = sshd`, `chroot("/var/empty")`, `seccomp` sandbox) to parse untrusted SSHv2 packets [111, 113].

![Figure: How regreSSHion (CVE-2024-6387) exploited an async-signal-unsafe syslog() call inside pre-auth sshd's SIGALRM LoginGraceTime handler to corrupt glibc malloc structures, and how OpenSSH 9.8 split sshd-session into a fresh execve() binary to randomize ASLR per connection.](diagrams/13-regresshion-privsep-split.svg)

In July 2024, Qualys disclosed `regreSSHion` (`CVE-2024-6387` [111]), an unauthenticated remote root vulnerability affecting `glibc`-based Linux `sshd` (`8.5p1` through `9.7p1`, accidentally reintroduced in October 2020 when commit `c3f86b9` stripped `#ifdef DO_LOG_SAFE_IN_SIGHAND` guards!). When a client connects to TCP `22` and fails to complete authentication within `LoginGraceTime` (default `120` seconds), the kernel delivers `SIGALRM` directly to the privileged root monitor process [111]. Inside `grace_alarm_handler()`, `sigdie()` called `syslog()`, which on `glibc` dynamically allocates `FILE` buffers and locale structures via `malloc()`/`free()`: *an async-signal-unsafe violation of POSIX signal rules*! By grooming `sshd`'s heap via crafted public-key packets and timing TCP stalls so `SIGALRM` fired mid-way through an interrupted `malloc()`/`free()` call in the main loop, an attacker corrupted `glibc` heap chunk metadata (`_IO_wfile_jumps` vtable pointers) inside the unsandboxed `UID 0` monitor process [111]!

Worse, why was winning a probabilistic `glibc` ASLR race practical over ~10,000 connections (~6–8 hours on 32-bit, days/feasible with leaks on 64-bit)? Because classic `sshd` created per-connection children via `fork()` without `execve()`, meaning every single connection inherited the exact same `ASLR` memory layout as the long-running parent `sshd` listener [111, 113]! OpenSSH `9.8` [113] delivered the permanent architectural cure alongside stripping `syslog()` from `SIGALRM`: splitting monolithic `sshd` into a tiny `sshd` listener binary, `sshd-session` (invoked via a fresh `execve()` on every accepted TCP connection, completely re-randomizing `ASLR` across `libc`, stack, and heap on every single connection!), and `sshd-auth` (`9.9+`, isolating pre-authentication code into an ephemeral binary unloaded from memory entirely once authentication succeeds!), paired with `PerSourcePenalties` automatic IP rate-limiting on pre-auth crashes [113].

## Distro, Immutable-OS, & Cloud Trade-Offs

Enterprise Linux fleets (`RHEL 9.4+`, `Ubuntu 24.04 LTS`, `Debian 12`) backported the `CVE-2024-6387` signal fix immediately and increasingly deploy OpenSSH `9.8+`/`9.9+` split binaries alongside `sshd_config.d/` drop-ins enforcing `PasswordAuthentication no`, `KbdInteractiveAuthentication no` (unless bound strictly to `PAM` OIDC/FIDO2), `AllowAgentForwarding no`, and `TrustedUserCAKeys` [109, 111, 113]. Cloud-native immutable platforms push even further: AWS `SSM Session Manager`, GCP `OS Login`, and `Tailscale SSH` eliminate public TCP port `22` inbound listeners altogether (tunneling over outbound mTLS/WireGuard channels), while `Talos Linux` removes `sshd`, `PAM`, and `shell` binaries completely from worker nodes so cluster administration occurs exclusively through mutual-TLS authenticated, RBAC-audited `talosctl` gRPC calls [34]!

## Seam Failures, CVEs, & Structural Bounds

Host authentication failures span misordered `PAM` stacks, forwarded `ssh-agent` hijacking, unvalidated Kerberos KDC responses, and async-signal/fork-ASLR flaws in network listeners.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `PAM` `sufficient` / Missing `account` Bypass | Recurring | `/etc/pam.d/*` stack configuration | `PAM` `auth` controls SSH key logins and `sufficient` honors downstream checks | SSH pubkey skips `auth` (only runs `account`), or early `sufficient` skips `pam_faillock` / `pam_nologin` | Use `substack` / `[default=die]` carefully and enforce `SSSD` `HBAC` inside PAM `account` [107, 108] |
| Kerberos KDC Spoofing ("Zombieland" / `krb5_validate=false`) | 2015-2024 | `pam_krb5` / misconfigured `SSSD` | Validating `AS-REP` against user password proves KDC authenticity | Rogue LAN KDC knowing phishing password returns forged `AS-REP` granting local `root`/`sudo` | Enforce `krb5_validate = true` verifying `TGS-REP` against restricted `/etc/krb5.keytab` [108] |
| Forwarded `ssh-agent` PKCS#11 RCE (`CVE-2023-38408`) | 2023 | OpenSSH `ssh-agent` (`ForwardAgent yes`) | Compromised jump host can only request one-time signatures from forwarded agent | Jump host sends `SSH_AGENTC_ADD_SMARTCARD_KEY` loading side-effecting `/usr/lib/*` `.so`s on client laptop for RCE | Disable `ForwardAgent`; use `ProxyJump -J` + `FIDO2` `-O verify-required` keys [110, 112] |
| `regreSSHion` (`CVE-2024-6387`) | 2024 | OpenSSH `sshd` `SIGALRM` + `glibc` | `SIGALRM` timeout handler terminates connection cleanly | Async-unsafe `syslog()` inside `SIGALRM` corrupts `glibc` heap in unsandboxed `UID 0` monitor (`fork`-cloned ASLR) | Upgrade to OpenSSH `9.8+`/`9.9+` (`_exit`-only signal handler + `execve` `sshd-session`/`sshd-auth` split + `PerSourcePenalties`) [111, 113] |

With single-host boot, Ring 0 self-protection, mandatory access control, `SUID`-free privilege, secret custody, and fleet SSH identity established across Parts I through III, Part IV ([Chapters 14](14-containers-escapes.md) through [19](19-confidential-containers.md)) confronts the defining challenge of modern Linux infrastructure: isolating untrusted multi-tenant containers, autonomous AI coding agents, cloud workload identities, and Confidential VMs at hyperscale.

## Inspecting on a Live Linux Host

Evaluate the effective merged `sshd` security configuration (`sshd -T` resolves all `Include /etc/ssh/sshd_config.d/*.conf` drop-ins) and check OpenSSH version (`>= 9.8` for binary split):

```bash
ssh -V
# sshd -T requires root / run0 to read host keys and evaluate effective settings
sshd -T 2>/dev/null | grep -E "^(passwordauthentication|permitrootlogin|pubkeyauthoptions|trustedusercakeys|allowagentforwarding|persourcepenalties)\b"
```

Inspect an OpenSSH certificate's validity window, principals, and critical options, or verify `PAM` `sshd` `account` stack ordering:

```bash
grep -vE "^#|^$" /etc/pam.d/sshd 2>/dev/null | head -n 16
```

Check `SSSD` domain status and confirm Kerberos ticket validation (`krb5_validate`) if enrolled in an enterprise directory:

```bash
sssctl domain-list 2>/dev/null || systemctl is-active sssd.service 2>/dev/null || true
grep -rn "krb5_validate" /etc/sssd/ 2>/dev/null || true
```
