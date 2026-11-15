# Killing SUID: From sudo and Polkit to systemd run0

## Overview

* **Link in the Chain:** Replaces the fragile in-process privilege-transition model (`SUID-root` `sudo`, `su`, `pkexec`) atop POSIX capabilities ([Chapter 9](09-capabilities-userns.md)) with out-of-process, IPC-brokered transient execution (`systemd` `run0` and `run0 --empower`).
* **Core Security Invariant:** Unprivileged processes never elevate credentials in-place via `S_ISUID` (`04000`) or file capabilities; instead, privilege transitions occur exclusively via IPC requests to `PID 1`, which authenticates the caller out-of-band and spawns a clean-room child from pristine state with an isolated pseudo-terminal (`PTY`) and optional non-`UID-0` ambient capabilities.
* **Deployment Profile Matrix:** Classic mutable distros still ship `sudo` and several `SUID` binaries (`/usr/bin/passwd`, `mount`, `fusermount3`) while `Fedora 41+`, `Arch`, and `Ubuntu 24.10+` also include `run0` (`systemd v256+`); hardened `bootc` / `CoreOS` profiles set `RestrictSUIDSGID=yes` or mount `/` `nosuid` with `run0`; immutable `Talos` omits interactive shells, `sudo`, and `SUID` completely.
* **Trusted Computing Base (TCB):** `systemd` (`PID 1` transient unit manager and PTY forwarder), `polkitd` authorization daemon, `Varlink` / `D-Bus` `SO_PEERCRED` + `pidfd` peer verification, and Linux TTY driver (`dev.tty.legacy_tiocsti=0`).
* **Integration Seam & Handoff:** Eliminates `argv`, `envp` (`ld.so`), `chroot`, `rlimit`, and `TIOCSTI` inheritance vulnerabilities during interactive elevation; delegates persistent daemon sandboxing and `D-Bus`/`Varlink` IPC mediation to [Chapter 11](11-systemd-dbus-sandboxing.md).

## Problem Statement & Threat Model

In November 1973, Dennis Ritchie patented the `set-user-ID` (`SUID`, `S_ISUID = 04000`) permission bit for Unix: whenever an unprivileged user executes a file owned by `root` with `04000` set, the kernel mutates `cred->euid = cred->suid = cred->fsuid = 0` inside the *calling process* across `execve(2)` [5, 91]. Half a century later, few mechanisms in operating-system history have compiled a more catastrophic vulnerability record [86, 87, 88, 89, 91].

Why do `sudo`, `pkexec`, `su`, `fusermount`, and dynamic-linker `SUID` paths suffer high-severity local root CVEs year after year despite intense code audits? Because *in-place privilege elevation violates clean-room isolation at the architectural level* [91, 94]. On Linux, `execve(2)` replaces a process's virtual memory mappings and resets signal handlers, yet almost every other facet of the process execution environment is inherited directly from the untrusted, unprivileged parent: the `argv[]` argument array (even degenerate `argc == 0` empty arrays!), the `envp[]` environment string table (`LANG`, `TZ`, `GLIBC_TUNABLES`, `LC_*`), open file descriptors `0..N`, the current working directory (`cwd`) and `chroot` root directory, resource limits (`RLIMIT_STACK`, `RLIMIT_AS`, `RLIMIT_FSIZE`), scheduling priorities, `cgroup` membership, audit loginuid, process group / session membership, and the controlling pseudo-terminal (`PTY`) [90, 91, 94]!

Consider the defender's impossible burden under a local unprivileged adversary (`UID 1000` or compromised web/container user) invoking `/usr/bin/sudo` or `/usr/bin/pkexec`. Before line one of `sudo`'s `main()` function even executes, the kernel maps the GNU C Library dynamic linker (`/lib64/ld-linux-x86-64.so.2`) into memory already running as `euid = 0` to parse ELF headers, environment tunables, and shared-library search paths [89, 94]! Once `main()` starts, complex C parsers must parse command-line flags, `sudoers` grammars, locale catalogs, Name Service Switch (`/etc/nsswitch.conf` `dlopen()` plugins [87]), and `PAM` stacks while defending against dozens of inherited kernel states set specifically to induce allocation failures, path confusion, or integer overflows. And when a `root` shell or administrative script temporarily drops privilege via `su - nonroot` on the *same* terminal session without allocating an isolated `PTY`, the unprivileged child historically called `ioctl(0, TIOCSTI, &ch)` to stuff `rm -rf` or `chmod +s /bin/bash\n` straight back into the parent `root` shell's input queue [90, 91]! Rather than patching `AT_SECURE` environment denylists forever, modern Linux kills `SUID` outright.

## Kernel & Userspace Mechanics

### Forensic Anatomy of the `SUID` Inheritance Surface

Tracing four landmark `SUID` compromises between 2021 and 2025 proves why every inherited attribute across `execve(2)` is an active weapon:

![Figure: Why SUID-root binaries fail structurally: elevating euid = 0 inside an untrusted caller's process tree inherits hostile argv[], envp[] (ld.so GLIBC_TUNABLES), chroot/NSS paths, rlimits, open descriptors, and controlling PTYs.](diagrams/10-suid-inherited-context-hazards.svg)

First, *`envp[]` and the Dynamic Linker (`Looney Tunables`, `CVE-2023-4911`)* [89, 94]. When the kernel executes a `SUID`, `SGID`, or file-capability binary (`cred->euid != cred->uid`), `create_elf_tables()` sets `AT_SECURE = 1` inside the ELF auxiliary vector (`auxv`) on the initial user stack. Seeing `AT_SECURE == 1`, `glibc` `ld.so` enters *secure-execution mode*, supposed to strip dangerous variables such as `LD_PRELOAD`, `LD_AUDIT`, and `LD_LIBRARY_PATH` [94]. Yet `glibc` 2.34+ also parsed `GLIBC_TUNABLES` inside `__tunables_init()` at the very earliest stage of dynamic linking using raw stack/minimal buffers: passing a crafted `GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=...` string triggered an out-of-bounds buffer overflow in `parse_tunables()`, overwriting `struct link_map`'s `l_info[DT_RPATH]` pointer so `ld.so` loaded `libc.so.6` directly out of an attacker-controlled directory `"."` as `UID 0` on Fedora, Ubuntu, and Debian [89]!

Second, *`argv[]` Edge Cases (`PwnKit` `CVE-2021-4034` and `Baron Samedit` `CVE-2021-3156`)* [86, 88]. POSIX conventions assume `argv[0]` holds the program name (`argc >= 1`), yet Linux `execve(path, {NULL}, envp)` legally permits `argc == 0`! Inside `Polkit`'s `SUID-root` `pkexec` utility, `for (n = 1; n < (guint) argc; n++)` skipped the loop when `argc == 0`, leaving `n = 1`; on the stack layout `argv[0] = NULL` sits immediately adjacent to `envp[0]`, so `path = g_strdup(argv[1])` read `envp[0]` out-of-bounds and `argv[1] = ...` *wrote a modified string pointer straight into `envp[0]`*, re-injecting `GCONV_PATH=.` after `ld.so` had already finished `AT_SECURE` scrubbing so `g_printerr()` `dlopen()`ed an attacker `.so` as `UID 0` (lurking in every desktop/server install for 12 years!) [88]. Meanwhile, in `sudo` `Baron Samedit` (`CVE-2021-3156` [86]), invoking `sudoedit -s '\'` bypassed command-line escaping checks meant for `MODE_RUN`, causing `set_cmnd()` to copy past a trailing single backslash `\` and corrupt `sudo`'s heap (`service_user` NSS struct pointers) for universal `UID 0` without even being listed in `/etc/sudoers`!

Third, *`chroot` and NSS Shared-Object Loading (`CVE-2025-32463`)* [87]. Disclosed in June 2025 across `sudo` `1.9.14` through `1.9.17`, `sudo`'s `-R` (`--chroot`) option called `chroot(user_Specified_dir)` *before* completing `sudoers` evaluation while running as `euid = 0`! When `glibc` subsequently resolved user/group accounts via Name Service Switch, it parsed `<attacker_chroot>/etc/nsswitch.conf`, saw `passwd: /woot1337`, and called `dlopen("/lib/libnss_/woot1337.so.2")` *inside the attacker's fake chroot directory*, executing arbitrary constructor code as `UID 0` [87]! Fourth, *shared Terminal `TIOCSTI` Injection* [90]: until Linux 6.2 introduced `CONFIG_LEGACY_TIOCSTI=n` (`sysctl dev.tty.legacy_tiocsti = 0`), any process holding an open descriptor to a controlling TTY could invoke `ioctl(tty_fd, TIOCSTI, &byte)` to stuff fake typed characters into the terminal's input buffer, hijacking parent shells the moment `su` or `sudo -u appuser` exited!

### `systemd` `run0` and `run0 --empower`: Clean-Room Brokered Privilege

Introduced by Lennart Poettering in `systemd v256` and expanded with `--empower` in `v257`–`v259` [91, 92], `run0` (implemented as a `argv[0]` personality of `systemd-run`) abolishes `SUID` completely: `ls -l /usr/bin/run0` shows normal `0755` permissions (`-rwxr-xr-x`, zero `SUID` bit, zero file capabilities!). How can an unprivileged binary grant root or administrative capabilities without `SUID`? By inverting the direction of process creation [91, 92]:

![Figure: Clean-room privilege elevation with systemd run0 and run0 --empower: unprivileged run0 sends an IPC request to PID 1, Polkit authenticates out-of-band, and PID 1 spawns a fresh transient service unit with an isolated PTY and optional non-root ambient capabilities.](diagrams/10-systemd-run0-clean-broker.svg)

When an engineer runs `run0 dnf upgrade` (or `run0` for an interactive session), the unprivileged `run0` client opens an IPC connection (`D-Bus` / `Varlink`) to `systemd` (`PID 1`) requesting a transient service unit [91, 92]. `PID 1` inspects the caller's unforgeable socket peer credentials (`SO_PEERCRED` + `pidfd`, covered in [Chapter 11](11-systemd-dbus-sandboxing.md)) and queries `polkitd` (`org.freedesktop.systemd1.manage-units`). `polkitd` spawns an isolated authentication agent attached to the user's TTY (checking group membership such as `wheel` + password/FIDO2 PAM verification without exposing the `run0` target binary to untrusted input!). Once `Polkit` returns `Authorization = yes`, `PID 1` forks the target command directly as a child of `PID 1`:

Look at every vulnerability class that vanishes instantaneously under this clean-room fork [91]:
First, the new process does *not* inherit the caller's `envp[]` (`GLIBC_TUNABLES`, `GCONV_PATH`, `LD_*`), `chroot`, `RLIMIT_*`, `umask`, signal mask, cgroup, or open file descriptors: `PID 1` constructs a minimal synthetic environment (`PATH`, `TERM`, `LANG` validated against strict UTF-8 syntax) from scratch! Second, `PID 1` allocates a brand-new kernel pseudo-terminal (`PTY` master/slave pair) exclusively for the transient unit; the unprivileged `run0` client on the outside merely copies raw stdin/stdout bytes across IPC sockets, meaning the elevated target and the unprivileged caller *never share a controlling TTY file descriptor* (`TIOCSTI` and `Landlock ABI v5` TTY `ioctl` attacks are structurally impossible) [90, 91]! Third, while elevated, `run0` emits ANSI `OSC 11` escape sequences tinting the terminal background a unmistakable warm reddish hue (`--background=`) and sets window title markers so a user never confuses a root shell with a normal shell [91, 92].

Even better, `run0 --empower` (`systemd v257`–`v259` [92]) eliminates the need to become `UID 0` at all for 90% of interactive administrative tasks! Instead of setting `UID = 0` (which breaks home-directory file ownership and bypasses DAC everywhere), `run0 --empower` spawns a session retaining the caller's own unprivileged `UID` (e.g., `UID 1000`), populated with elevated *Ambient POSIX Capabilities* (`CAP_NET_ADMIN`, `CAP_BPF`, `CAP_DAC_READ_SEARCH` per policy) plus an environment-registered Polkit action token allowing `systemctl` and `busctl` operations without re-prompting [92].

### Enforcing `SUID`-Free Systems: `NoNewPrivileges` and `nosuid`

Deploying `run0` unlocks the ultimate payoff: turning off `SUID` kernel-wide across userspace workloads [91, 93, 95]! Setting `NoNewPrivileges=yes` (`prctl(PR_SET_NO_NEW_PRIVS, 1)`) in user session slices (`user@.service`), container runtimes, or `MountFlags=nosuid` on `/usr` and `/home` instructs `execve(2)` inside Ring 0 to ignore every remaining `S_ISUID`, `S_ISGID`, and `security.capability` xattr on disk. Even if an attacker discovers a brand-new `argc == 0` or `ld.so` bug in a forgotten legacy binary on `/usr`, `AT_SECURE` elevation never triggers because `cred->euid` never changes!

## Distro, Immutable-OS, & Cloud Trade-Offs

Can a general-purpose Linux workstation strip *every* `SUID` bit (`find /usr -perm /6000`) today? Nearly so, with three transitional caveats [91, 95]: (1) `Polkit`'s own authentication helper (`polkit-agent-helper-1`) historically used `SUID-root` to talk to `PAM` `pam_unix` (`/etc/shadow`), though `systemd` and modern `Polkit` move shadow verification into socket-activated `systemd-userdbd` / `unix_chkpwd` helpers; (2) unprivileged FUSE mounts (`fusermount3`) and legacy `/bin/mount` carry `SUID` on desktop installs unless replaced by `systemd-mount` IPC; and (3) Chromium/Electron binaries bundle a fallback `chrome-sandbox` `SUID` binary used only when user namespaces are blocked without an `AppArmor` profile ([Chapter 9](09-capabilities-userns.md)). By contrast, cloud container images (`Distroless`, `Chainguard Wolfi`), immutable Kubernetes OSes (`Talos`, `Bottlerocket`), and modern `Fedora`/`CoreOS` `bootc` server templates strip `sudo` and `SUID` binaries completely, leaving zero `04000` inodes on the root filesystem [34, 91].

## Seam Failures, CVEs, & Structural Bounds

Four years of headline Linux LPEs read like an obituary for `SUID-root`:

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| Baron Samedit (`CVE-2021-3156`) | 2021 | `sudo` (`sudoedit -s`) | Argument escaping before `sudoers` check bounds heap writes | Trailing single backslash `\` overflows `user_args` heap buffer into NSS `service_user` pointers for `UID 0` | Patch `sudo` `MODE_EDIT` flags; migrate interactive elevation to `SUID`-free `run0` [86, 91] |
| PwnKit (`CVE-2021-4034`) | 2022 | `Polkit` `pkexec` (`SUID-root`) | `execve` always passes `argc >= 1` | `argc == 0` reads/writes `argv[1]` OOB into `envp[0]`, injecting `GCONV_PATH=.` after `ld.so` `AT_SECURE` scrub | Check `argc < 1` at entry; strip `SUID` from `pkexec` or replace with `run0` [88, 91] |
| `TIOCSTI` Terminal Pushback | 1985-2023 | Linux TTY `ioctl` + `su`/`sudo` | Child running under lower UID on shared TTY cannot inject parent commands | Child calls `ioctl(0, TIOCSTI, &c)` to stuff shell commands into `root`'s controlling TTY input queue | Set `sysctl dev.tty.legacy_tiocsti=0` (`Linux 6.2+`), `sudo use_pty`, or `run0` isolated PTY [90, 91] |
| Looney Tunables (`CVE-2023-4911`) | 2023 | `glibc` `ld.so` (`GLIBC_TUNABLES`) | `AT_SECURE` dynamic-linker startup code is memory-safe against hostile `envp` | Crafted duplicate tunable overflows `ld.so` buffer before `main()`, hijacking `DT_RPATH` search path as `UID 0` | Fix `parse_tunables()`, enforce `NoNewPrivileges=yes`, and eliminate `SUID` binaries [89, 93] |
| `sudo` `chroot` NSS LPE (`CVE-2025-32463`) | 2025 | `sudo` `-R` (`--chroot`) | Calling `chroot()` prior to `sudoers` rejection safely sandboxes path lookups | `glibc` NSS parses `<user_chroot>/etc/nsswitch.conf` and `dlopen()`s attacker shared library as `UID 0` | Remove pre-auth `chroot()` in `sudo 1.9.17p1`; spawn clean-room units from `PID 1` via `run0` [87, 91] |

Notice the structural bound exposed by moving from `SUID` to `run0`: *eliminating `SUID` transfers trust from the dynamic linker (`ld.so`) onto the userspace IPC broker (`D-Bus`, `Varlink`, `polkitd`, and `PID 1`)* [91, 98]! If `PID 1` or `D-Bus` misidentifies *which* client process sent an IPC request (as happened in `Polkit` `CVE-2021-3560`!), brokered privilege fails just as swiftly as `SUID`. Securing long-running daemons and race-free IPC peer authentication is the exact subject of [Chapter 11](11-systemd-dbus-sandboxing.md).

## Inspecting on a Live Linux Host

Audit every `SUID` (`-4000`) and `SGID` (`-2000`) executable currently present on `/usr` (an ideal hardened server or container image returns zero or near-zero lines!):

```bash
find /usr/bin /usr/sbin /usr/libexec -perm /6000 -ls 2>/dev/null | head -n 20
```

Verify that `run0` carries zero `SUID` permissions (`-rwxr-xr-x`) and check whether legacy `TIOCSTI` terminal injection is disabled in the kernel:

```bash
ls -la $(command -v run0 2>/dev/null) 2>/dev/null || systemd-run --version | head -n 2
sysctl dev.tty.legacy_tiocsti 2>/dev/null || true
```

Check `sudo` patch level (`>= 1.9.17p1` closes `CVE-2025-32463`) and whether `use_pty` isolation is active in `/etc/sudoers`:

```bash
sudo --version 2>/dev/null | head -n 2
# Inspecting /etc/sudoers requires root / run0
grep -rn "use_pty" /etc/sudoers /etc/sudoers.d/ 2>/dev/null || true
```
