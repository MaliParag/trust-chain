# Killing SUID: From sudo and Polkit to systemd run0

## Overview

* **Link in the Chain:** Replaces fragile in-process privilege transitions (`S_ISUID` `04000` binaries such as `sudo`, `su`, `pkexec`, and `mount`) atop POSIX capabilities ([Chapter 9](09-capabilities-userns.md)) with out-of-process, IPC-brokered transient execution (`systemd` `run0` and `run0 --empower`).
* **Core Security Invariant:** Unprivileged callers never mutate credentials in-place across `execve(2)` inside a hostile inherited process environment; instead, privilege elevation occurs strictly via authenticated IPC requests to `PID 1` (and `systemd-ptybrokerd`), which forks a clean-room service unit with synthetic `envp[]`, an isolated pseudo-terminal (`PTY`), and optional non-`UID-0` ambient capabilities (`--empower`).
* **Deployment Profile Matrix:** `Fedora 41+`, `Arch`, and modern `systemd` (`v256` through `v262+`) distributions ship `run0` and `run0 --empower`; `Ubuntu 25.10+` transitions `sudo` to memory-safe `sudo-rs` while adding `run0`; `bootc`/`CoreOS` profiles pair `NoNewPrivileges=yes` and `nosuid` mounts with `systemd-mountfsd`/`nsresourced`; `Chainguard Wolfi`, `Distroless`, and `Talos` ship zero `SUID` binaries.
* **Trusted Computing Base (TCB):** `systemd` (`PID 1` transient service manager, `src/run/run.c`, and `systemd-ptybrokerd.service`), `polkitd` authorization engine, `D-Bus`/`Varlink` `SO_PEERCRED` + `SO_PEERPIDFD` peer credentials, Linux `fs/exec.c` (`no_new_privs`), and `drivers/tty/tty_io.c` (`dev.tty.legacy_tiocsti=0`).
* **Integration Seam & Handoff:** Eliminates `argv[]` (`argc == 0`), `envp[]` (`ld.so` `GLIBC_TUNABLES`), `chroot` NSS `dlopen()`, `RLIMIT_*`, file-descriptor, and `TIOCSTI` inheritance vulnerabilities during privilege elevation; hands off persistent daemon sandboxing and race-free IPC peer authentication to [Chapter 11](11-systemd-dbus-sandboxing.md).

## Problem Statement & Threat Model

In November 1973, Dennis Ritchie filed `US Patent 4,135,240` for Unix's `set-user-ID` (`S_ISUID = 04000`) inode permission bit: whenever an unprivileged user executes an executable owned by `UID 0` with `04000` set, `bprm_creds_from_file()` and `bprm_fill_uid()` inside `fs/exec.c` mutate `cred->euid = cred->suid = cred->fsuid = 0` directly inside the *calling process* across `execve(2)` [318, 319]. Notice how many fragile guard checks `fs/exec.c` had to accumulate just to keep `bprm_fill_uid()` from failing instantly: the kernel must check `!mnt_may_suid(file->f_path.mnt)` (`nosuid` mounts), `!task_no_new_privs(current)` (`PR_SET_NO_NEW_PRIVS` [320]), and `!(bprm->unsafe & LSM_UNSAFE_PTRACE)` (blocking the classic race where an unprivileged attacker `ptrace(PTRACE_ATTACH)`es a child process right before it executes `/usr/bin/sudo` to hijack `UID 0` syscalls!). Even with those Ring 0 checks intact, no privilege boundary in Unix history accumulated a more devastating fifty-year record of local root exploits (`Chen, Wagner, & Dean` [321]; `Tsafrir et al.` [322]).

Why do `sudo`, `pkexec`, `su`, `mount`, `fusermount`, and `glibc`'s dynamic linker suffer critical local privilege-escalation (`LPE`) vulnerabilities decade after decade despite continuous code review? Because *in-place credential elevation across `execve(2)` violates clean-room isolation by design* [6, 321, 322]. As Hao Chen, David Wagner, and Drew Dean formalized in *Setuid Demystified* [321] (and Dan Tsafrir et al. extended [322]), POSIX processes maintain an asymmetric triple of real, effective, and saved-set UIDs (`ruid`, `euid`, `suid`), where legacy `setuid()` and `seteuid()` calls behave differently depending on whether `euid == 0` at call time, and where temporarily dropping privileges (`seteuid(ruid)`) leaves `suid = 0` recoverable in memory by any shellcode or ROP gadget! Even worse, if an attacker exhausts `RLIMIT_NPROC` (`ulimit -u`) under the target UID before invoking a legacy `SUID-root` helper that calls `setuid(target_uid)` without checking its return code, `setuid()` fails with `-EAGAIN` and the program continues executing user actions as `UID 0` [321, 322]!

Beyond UID state-machine traps, `execve(2)` replaces virtual memory mappings and resets caught signal handlers to `SIG_DFL`, yet the newly elevated `euid = 0` process inherits more than a dozen execution attributes straight from its untrusted `UID 1000` parent: the `argv[]` argument vector (including degenerate `argc == 0` empty arrays!), the `envp[]` environment variable array (`GLIBC_TUNABLES`, `LANG`, `LC_*`, `TZ`), open file descriptors `0..N` (or deliberately closed `0, 1, 2` descriptors causing subsequent `open("/etc/shadow")` calls inside the `SUID` binary to bind onto `STDOUT_FILENO = 1`, tricking `perror()` error messages into corrupting `/etc/shadow`!), current working directory (`cwd`), `chroot` root directory, process resource limits (`RLIMIT_STACK`, `RLIMIT_AS`, `RLIMIT_FSIZE` triggering `SIGXFSZ` mid-write to truncate `/etc/passwd` or `/etc/mtab`!), signal masks (`sigprocmask` blocking `SIGALRM`/`SIGTERM`), `umask`, `cgroup` slice and OOM score, scheduler policy, and the controlling terminal (`PTY`) [6, 319, 321, 323]!

Trace the impossible defensive surface this creates against a local unprivileged attacker (`UID 1000` or compromised web/container service) invoking `/usr/bin/sudo` or `/usr/bin/pkexec`. *Before line one of `main()` even runs*, the kernel maps `/lib64/ld-linux-x86-64.so.2` (`glibc` `ld.so`) into memory already executing as `euid = 0` to parse ELF headers, tunables, and shared-object search paths over attacker-supplied `envp[]` (`Looney Tunables`, `CVE-2023-4911` [67, 324]). Once `main()` begins, 170,000+ lines of C in `sudo` (plus `glibc` locale/syslog/NSS subsystems and `PAM` plugin stacks) must parse complex `sudoers` host/command grammars (`CVE-2021-3156` [64], `CVE-2025-32462` [325]), handle `--chroot` flags (`CVE-2025-32463` [65]), and format error logs (`CVE-2023-6246` [326]) without a single memory error or confused-deputy lookup. Worse still, when a privileged session transitions downward (`su - nonroot`) on a shared terminal without allocating a separate `PTY`, the unprivileged child historically stuffed shell commands straight back into `root`'s terminal input queue via `ioctl(0, TIOCSTI, &ch)` (`CVE-2017-5226` [327, 328]). Rather than patching `AT_SECURE` denylists forever, modern Linux retires `SUID` architecturally via `systemd` `run0` [6, 329].

## Kernel & Userspace Mechanics

### Forensic Anatomy of the `SUID` Inheritance Surface (2021 to 2025)

Examining four classes of `SUID` compromises between 2021 and 2025 demonstrates why every inherited process attribute across `execve(2)` acts as an exploit primitive:

![Figure: Why SUID-root binaries fail structurally: elevating euid = 0 inside an untrusted caller's process tree inherits hostile argv[], envp[] (ld.so GLIBC_TUNABLES), chroot/NSS paths, rlimits, open descriptors, and controlling PTYs.](diagrams/10-suid-inherited-context-hazards.svg)

First, *`envp[]` and Pre-`main()` Dynamic Linking (`Looney Tunables` `CVE-2023-4911` and `CVE-2023-6246`)* [67, 324, 326]. When `fs/binfmt_elf.c` (`create_elf_tables()` [319]) launches a binary whose `euid != uid` (or `egid != gid`, or file capabilities raised `Permitted`), it writes `AT_SECURE = 1` into the ELF auxiliary vector (`auxv`) on the initial user stack:

```text
High VA -> [ env/arg strings ] [ auxv: AT_SECURE=1 ... ] [ NULL ] [ envp[0..m] ] [ NULL ] [ argv[0..argc-1] ] [ argc ] <- %rsp
```

Observing `AT_SECURE == 1`, `glibc` `ld.so` enters secure-execution mode and iterates over `UNSECURE_ENVVARS` (`sysdeps/generic/unsecvars.h` [324]) to scrub `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, `GCONV_PATH`, and `HOSTALIASES`. Yet denylisting environment variables inside a complex C runtime is structurally brittle: in `glibc 2.34+`, `__tunables_init()` (`elf/dl-tunables.c`) parsed `GLIBC_TUNABLES` at the very start of `ld.so` initialization before `main()` ran. Passing a crafted duplicate tunable string (`GLIBC_TUNABLES=glibc.malloc.mxfast=glibc.malloc.mxfast=...`) triggered a pointer-increment logic flaw in `parse_tunables()` (`CVE-2023-4911` [67, 324]), overflowing a minimal `ld.so` allocation into `struct link_map`'s `l_info[DT_RPATH]` pointer so `ld.so` loaded `./libc.so.6` directly from an attacker-controlled working directory `"` as `UID 0`! Months later, Qualys uncovered `CVE-2023-6246` [326] inside `glibc`'s `__vsyslog_internal()`: passing a $>1024$-byte `argv[0]` program name to `SUID` `su` or `sudo` overflowed a heap buffer during `syslog()` authentication logging.

![Figure: Stack, dynamic-linker, and pre-authentication chroot mechanics across Looney Tunables (CVE-2023-4911), PwnKit (CVE-2021-4034), and sudo --chroot (CVE-2025-32463), contrasted against clean-room transient service spawning in systemd run0.](diagrams/10-extra-pwnkit-looney-envp-hazard.svg)

Second, *`argv[]` Degeneracy and Escaping Bugs (`PwnKit` `CVE-2021-4034` and `Baron Samedit` `CVE-2021-3156`)* [64, 66, 330]. Although C textbooks assume `argc >= 1`, Linux `execve(path, {NULL}, envp)` historically allowed `argc == 0`! Look at the stack diagram above when `argc == 0`: `argv[0]` holds the terminating `NULL` pointer, and *`argv[1]` aliases `envp[0]` directly*! Inside Polkit's `SUID-root` `pkexec` binary (`CVE-2021-4034`, present since May 2009 [66]), argument parsing began with `for (n = 1; n < (guint) argc; n++)`. With `argc == 0`, the loop never executed, leaving `n = 1`; `pkexec` then read `path = g_strdup(argv[1])` (`envp[0] = "value"`) and resolved it via `g_find_program_in_path()` (using `PATH=GCONV_PATH=.` to return `"GCONV_PATH=./value"`) before executing `argv[1] = s`, which *overwrote `envp[0]` with `"GCONV_PATH=./value"` after `ld.so` had already finished `AT_SECURE` scrubbing*! Calling `g_printerr()` with an invalid `CHARSET` immediately caused `iconv_open()` to `dlopen()` an attacker shared library as `UID 0` [66]. Following `PwnKit`, Ariadne Conill and Kees Cook merged commit `dcd46d897adb` (`fs/exec.c`, Linux 5.18+ [330]) forcing `execve(2)` with `argc == 0` to inject a single empty `""` `argv[0]` string and warn in `dmesg`. Meanwhile, `sudo`'s `Baron Samedit` (`CVE-2021-3156` [64]) proved that even normal `argc >= 2` parsing fails in C: `sudoedit -s '\'` reached `set_cmnd()` without escaping backslashes, stepping past the `'\0'` terminator of a trailing `\` to smash heap `service_user` NSS structs for universal `UID 0` without any `/etc/sudoers` entry (followed in 2023 by `sudoedit` `CVE-2023-22809` arbitrary file editing via `--` in `SUDO_EDITOR` [331]), while Qualys's `Sequoia` exploit (`CVE-2021-33909` [323]) weaponized `SUID` `/bin/mount` and `systemd` `/proc/self/mountinfo` readers to trigger a `size_t`-to-`int` integer truncation inside `fs/seq_file.c` via $>1\text{ GiB}$ nested directory paths!

Third, *Pre-Authentication `chroot` and `sudoers` Scope Bugs (`CVE-2025-32463` and `CVE-2025-32462`)* [65, 325]. Disclosed by Rich Mirch in June 2025, `CVE-2025-32463` (`sudo` `1.9.14` through `1.9.17` [65]) demonstrated fatal confused-deputy ordering: `sudo -R <dir>` (`--chroot`) invoked `chroot(user_dir)` as `euid = 0` *during path resolution prior to completing `sudoers` authorization*! When `glibc` Name Service Switch (`NSS`) subsequently looked up user/group entries, it opened `<user_dir>/etc/nsswitch.conf`, parsed an attacker-controlled module line (`passwd: /pwn`), and executed `dlopen("/lib/libnss_/pwn.so.2")` *inside the unprivileged user's directory as `UID 0`*! Alongside it, `CVE-2025-32462` [325] revealed that `sudo -h <remote_hostname>` (`--host`, intended strictly for listing rules via `-l`) lacked an enforcement check when executing commands, letting users authorized only on a dev workstation in shared LDAP/`sudoers` files execute `root` commands on production servers!

Fourth, *Controlling Terminal `TIOCSTI` Injection (`CVE-2017-5226`)* [327, 328]. Whenever `su - target_user`, `sudo` (without `Defaults use_pty`), or older `bubblewrap` sandboxes (`CVE-2017-5226` [327]) spawned a lower-privileged child connected to the caller's `/dev/pts/N` terminal descriptor, that child could call `ioctl(STDIN_FILENO, TIOCSTI, &byte)` (`drivers/tty/tty_io.c`) to push forged keystrokes into the kernel TTY flip buffer; the instant the child exited, the parent `root` shell read and executed those injected bytes as interactive commands! Linux 6.2 finally severed unprivileged `TIOCSTI` via `CONFIG_LEGACY_TIOCSTI=n` (`sysctl dev.tty.legacy_tiocsti = 0`, requiring `CAP_SYS_ADMIN` [328]).

### `systemd` `run0` (`v256+`) and `run0 --empower` (`v259+`): Brokered Clean-Room Privilege

Engineered by Lennart Poettering in `systemd v256` and expanded through `v259`–`v262+` (`src/run/run.c` and `man/run0.xml` [6, 329, 332]), `run0` eliminates `SUID` completely: `/usr/bin/run0` is an unprivileged `0755` symlink to `systemd-run` carrying *zero* `S_ISUID` bit and *zero* `security.capability` xattrs. Instead of mutating `cred->euid` inside the caller's tainted process, `run0` inverts the direction of process creation through `PID 1` [6, 329]:

![Figure: Clean-room privilege elevation with systemd run0 and run0 --empower: unprivileged run0 sends an IPC request to PID 1, Polkit authenticates out-of-band, and PID 1 spawns a fresh transient service unit with an isolated PTY and optional non-root ambient capabilities.](diagrams/10-systemd-run0-clean-broker.svg)

When an administrator invokes `run0 dnf update` (or `run0` for an interactive login shell), `src/run/run.c` connects over `D-Bus` / `Varlink` to `systemd` (`PID 1`), or, for interactive shells on `v260+`, to `systemd-ptybrokerd.service` (`io.systemd.PTYBroker.acquire-pty-with-shell`, manageable via `ptyctl(1)` [329]). `PID 1` reads the client's kernel-verified socket peer identity (`SO_PEERCRED` + `SO_PEERPIDFD`, detailed in [Chapter 11](11-systemd-dbus-sandboxing.md)) and queries `polkitd` [333]. `polkitd` launches an isolated authentication agent on the session TTY to verify `wheel`/`sudo` group policy plus password or hardware `FIDO2` PAM credentials out-of-band; `run0` itself never touches passwords or `/etc/shadow`! Once Polkit authorizes the action (with temporary session timestamps revocable on demand via `run0 -k` or `run0 -K`, and pre-validatable via `run0 -v` in `v262+` [329]), `PID 1` spawns the requested command as a fresh transient service unit (`run-u*.service`).

Every single `SUID` vulnerability class collapses under `PID 1` spawning [6, 329]:
The transient service inherits *nothing* from the unprivileged caller's memory, stack, `envp[]` (`GLIBC_TUNABLES`, `GCONV_PATH`, `LD_*`), `argv[0]` tricks, `chroot`, `umask`, `RLIMIT_*`, `sigprocmask` (`run.c` explicitly restores `SIGPIPE` default disposition since normal daemons ignore `SIGPIPE`), or stray file descriptors; `PID 1` synthesizes a clean environment (`PATH`, `USER`, `HOME`, `$SUDO_UID`, `$SUDO_GID`, `$SUDO_USER`, structured journald `ELEVATED_UID` audit fields, and strictly UTF-8-validated `LANG`/`TERM`, plus explicit `--setenv=` allowlists). Furthermore, `src/run/run.c` sets `XDG_SESSION_CLASS=user-early-light` when elevating to `root` or `--empower` (`--lightweight=auto`), instructing `pam_systemd` not to spin up a heavy redundant `user@0.service` D-Bus user manager for a five-second administrative command [329]!
By default on terminals, `run.c` selects `--pty-late` (`arg_pty_late = true` whenever password prompts are active [329]): `run0` leaves raw terminal input untouched while `polkit-tty-ask-password-agent` collects the user's passphrase or `FIDO2` PIN directly on the session TTY (so the unprivileged `run0` process never even sees password keystrokes!), and only *after* Polkit authorization succeeds and the transient unit activates does `PID 1` / `systemd-ptybrokerd` attach a dedicated kernel pseudo-terminal (`PTY` master/slave pair) for the elevated command while `ptyfwd.c` proxies raw stdin/stdout byte streams over IPC sockets [6, 329]. Because the elevated process and unprivileged caller *never share a controlling TTY file descriptor*, `TIOCSTI` and terminal `ioctl` escapes are structurally impossible even on older kernels! Meanwhile, `shell_prompt_hue()` in `src/run/run.c` [329] emits ANSI SGR background-tint sequences (`--background=`) coloring the terminal reddish (`hue 0`) when running as `root`, orange (`hue 30`) under `--empower`, and yellowish (`hue 60`) when switching to another non-root UID, paired with OSC 3008 shell-context markers so operators can never mistake a privileged prompt for an unprivileged tab.

Introduced in `systemd v259` [329, 332], `run0 --empower` goes one step further: *interactive administrative elevation without `UID 0`*. Running editors, `git`, or diagnostic tools (`tcpdump`, `bpftool`) as `UID 0` notoriously litters `$HOME` with `root`-owned files and grants blanket `DAC` bypass. Invoking `run0 --empower` keeps the transient session running under the *invoking user's own unprivileged UID* (`UID 1000`), while `PID 1` populates its `AmbientCapabilities` (`CapAmb` = all available capabilities from [Chapter 9](09-capabilities-userns.md)) and adds the `empower` supplemental group (authorized by default Polkit rules for `systemctl` and `busctl` management) [329, 332]! Notice the exact security trade-off documented in `man/run0.xml` [329]: `--empower` is ideal when an administrator wants elevated capabilities on their own trusted account without `UID 0` file-ownership side effects, whereas full `UID 0` `run0` should be used if untrusted processes might already be running under `UID 1000` (since same-UID sibling processes can `ptrace` or signal another `UID 1000` process unless `Yama` `ptrace_scope >= 2` or LSM confinement blocks them).

### Sealing a `SUID`-Free OS: `NoNewPrivileges`, `nosuid`, and Varlink Mount Brokers

Replacing `sudo` and `su` with `run0` unlocks kernel-wide `SUID` abolition [6, 320, 334]. Setting `NoNewPrivileges=yes` in `/etc/systemd/system.conf` (or per-session slices via `prctl(PR_SET_NO_NEW_PRIVS, 1)` [320]) paired with `nosuid` mount flags across `/usr`, `/home`, `/var`, and `/tmp` causes `fs/exec.c` inside Ring 0 to ignore every `S_ISUID`, `S_ISGID`, and `security.capability` xattr system-wide! Historically, desktop and container hosts could not set `NoNewPrivileges=yes` globally because unprivileged container runtimes needed `SUID-root` `/usr/bin/newuidmap` and `/usr/bin/newgidmap` to program subordinate `uid_map` ranges, while desktop file managers needed `SUID-root` `/bin/mount` and `fusermount3`. Modern `systemd` (`v256+`) eliminates both holdouts via two brokered Varlink daemons [334]: `systemd-nsresourced.service(8)` delegates dynamic `64K` subordinate UID/GID ranges to unprivileged `user_namespace` file descriptors (`nsfs` `ioctl`s) over Varlink without any `SUID` helper, and `systemd-mountfsd.service(8)` mounts `dm-verity`-verified Disk Images (`DDI`s) on behalf of unprivileged callers after Polkit verification, returning isolated mount-tree file descriptors (`fsmount(2)` / `open_tree(2)`) cleanly across IPC!

## Distro, Immutable-OS, & Cloud Trade-Offs

Between 2024 and 2026, Linux distributions converged on two complementary paths to eradicate C `SUID` vulnerabilities: memory-safe Rust `sudo` drop-in replacements (`sudo-rs` [335, 336]) and `SUID`-free IPC brokers (`run0` [6, 337]), while cloud container images strip `SUID` completely [45, 338]:

| Elevation Mechanism | `S_ISUID` Bit? | `ld.so` `AT_SECURE` Surface? | Default `PTY` & `envp` Isolation | Deployment Adoption (`2025-2026`) |
|---|---|---|---|---|
| Legacy C `sudo` (`1.9.17p1+`) | Yes (`04111`) | Exposed pre-`main()` (`glibc`) | Opt-in (`Defaults use_pty`) | Legacy `RHEL`, `Debian`, `SUSE` servers [64, 65] |
| `OpenBSD doas` (`opendoas`) | Yes (`04755`) | Exposed pre-`main()` (`libc`) | Minimal `envp`; shared TTY | Minimalist `Alpine` / BSD-inspired hosts [339] |
| `sudo-rs` (Rust `sudo`/`su`) | Yes (`04755`) | Still runs `glibc` `ld.so` as `UID 0`! | Enforces `use_pty` & strict Rust parser | Default `sudo` in `Ubuntu 25.10+` [335, 336] |
| `systemd` `run0` / `--empower` | None (`0755`) | Zero (`PID 1` clean fork!) | Isolated `ptybrokerd` `PTY` + clean `envp` | `Fedora 41+`, `Arch`, `Ubuntu`, `bootc` [6, 329, 337] |
| Zero-`SUID` Immutable / Cloud | None (`nosuid`) | Zero (`NoNewPrivileges=yes`) | API-only (`Talos`) or SSH/SSM root | `Talos`, `Wolfi`, `Distroless`, `CoreOS` [45, 338] |

Observe the crucial architectural distinction between `sudo-rs` (`Ubuntu 25.10+` [335, 336]) and `run0` (`Fedora` / `systemd` [6, 329]): rewriting `sudo` in safe Rust (limiting scope to core `sudoers` grammars and turning `use_pty` on by default) eliminates internal C parser and heap overflows inside `sudo` itself (`Baron Samedit` `CVE-2021-3156`), while preserving near-exact CLI compatibility for decades of operational Ansible playbooks and automation scripts. However, because `sudo-rs` remains a `SUID-root` ELF dynamically linked against `glibc` and `libpam`, invoking `/usr/bin/sudo` *still maps `ld-linux-x86-64.so.2` as `euid = 0` inside the caller's inherited process context*, meaning dynamic-linker bugs (`Looney Tunables` `CVE-2023-4911`), `glibc` `syslog`/NSS C bugs (`CVE-2023-6246`), or C PAM module flaws remain reachable until `NoNewPrivileges=yes` and `run0` retire `SUID` altogether! In cloud-native production (`Chainguard Wolfi`, `Google Distroless` [338], and `Talos Linux` [45]), images ship *neither* `sudo` nor any `04000`/`02000` inode on disk (`find / -perm /6000` returns empty), treating interactive privilege escalation inside immutable workloads as an anti-pattern.

## Seam Failures, CVEs, & Structural Bounds

Five years of critical advisories across `sudo`, `pkexec`, `glibc`, and Linux TTYs illustrate why `SUID` failed at every layer of userspace startup:

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `CVE-2017-5226` (`TIOCSTI` Escape) | 2017-2023 | `drivers/tty/tty_io.c` + `su`/`bwrap` | Unprivileged child on shared TTY cannot inject parent commands | Child calls `ioctl(0, TIOCSTI, &c)` to push shell commands into `root`'s TTY input queue | Set `sysctl dev.tty.legacy_tiocsti=0` (`Linux 6.2+`) and isolate `PTY` via `run0` [327, 328, 329] |
| Baron Samedit (`CVE-2021-3156`) | 2021 | `sudo` (`sudoedit -s`) | Pre-`sudoers` backslash escaping bounds heap copies | Trailing single `\` steps past NUL terminator, overflowing `user_args` into NSS `service_user` structs | Patch `sudo`; replace C parser with `sudo-rs` or `SUID`-free `run0` [6, 64, 335] |
| PwnKit (`CVE-2021-4034`) | 2022 | `Polkit` `pkexec` (`SUID-root`) | `execve(2)` always supplies `argc >= 1` | `argc == 0` reads/writes `argv[1]` OOB into `envp[0]`, injecting `GCONV_PATH=.` post-`ld.so` scrub | Inject dummy `argv[0]` in `fs/exec.c` (`Linux 5.18+`) and strip `SUID` via `run0` [6, 66, 330] |
| `sudoedit` Arbitrary Write (`CVE-2023-22809`) | 2023 | `sudo` `SUDO_EDITOR` | `--` separator sanitizes user-controlled editor env vars | Extra `--` in `EDITOR="vim -- /etc/passwd"` tricks `sudoedit` into editing arbitrary root files | Reject `--` in editor env vars (`sudo 1.9.12p2`); scrub caller `envp` in `run0` [329, 331] |
| Looney Tunables (`CVE-2023-4911`) | 2023 | `glibc` `ld.so` (`GLIBC_TUNABLES`) | Pre-`main()` `AT_SECURE` dynamic linker code is memory-safe | Crafted duplicate tunable overflows `ld.so` buffer, hijacking `DT_RPATH` to load `./libc.so.6` as `UID 0` | Fix `parse_tunables()`, enforce `NoNewPrivileges=yes`, and abolish `SUID` [67, 320, 324] |
| `glibc` `syslog` Overflow (`CVE-2023-6246`) | 2024 | `glibc` `__vsyslog_internal` | Logging auth failures inside `SUID` `su`/`sudo` is safe | Oversized `argv[0]` ($>1024$ B) triggers heap buffer overflow inside `syslog()` as `euid = 0` | Patch `glibc` `vsyslog`; spawn elevated tasks from `PID 1` (`run0`) [6, 326] |
| `sudo --host` Bypass (`CVE-2025-32462`) | 2025 | `sudo` `-h` (`--host`) option | `-h` host override applies only to `sudo -l` listing | Executing `sudo -h devbox cmd` enforces `devbox`'s LDAP/`sudoers` rule on a restricted production host | Upgrade to `sudo 1.9.17p1` or centralize local Polkit/SSH cert policy [325, 333] |
| `sudo --chroot` NSS LPE (`CVE-2025-32463`) | 2025 | `sudo` `-R` (`--chroot`) | Pre-`sudoers` `chroot(user_dir)` safely confines lookups | `glibc` NSS reads `<user_dir>/etc/nsswitch.conf` and `dlopen()`s attacker `.so` as `UID 0` | Remove pre-auth `chroot()` (`sudo 1.9.17p1`); eliminate `SUID` via `run0` [6, 65] |

### Structural Bounds of IPC-Brokered Privilege

Moving from `SUID` to `run0` eliminates the inherited-process attack surface while concentrating trust squarely onto the *userspace IPC and authorization broker (`D-Bus`, `Varlink`, `polkitd`, and `PID 1`)* [6, 329, 333]. Three explicit operational boundaries merit close engineering scrutiny when deploying `run0` across workstations and servers:

First, callers and wrapper scripts must never force `run0 --pipe` onto untrusted interactive programs when invoked from an administrative terminal, because `--pipe` intentionally passes the caller's raw `STDIN`/`STDOUT`/`STDERR` descriptors through to support non-interactive shell pipelines (`run0 cat /etc/shadow | wc -l`), bypassing `PTY` isolation (`--pty-late` is automatically selected whenever all three standard streams attach to a TTY [329]). Second, as noted earlier for `run0 --empower` [329, 332], retaining the invoking user's non-root `UID 1000` while raising `CapAmb` avoids `root` file-ownership pollution in `$HOME`, yet shares the `UID 1000` security principal with every background process in the user's desktop or SSH session; unless `Yama` `kernel.yama.ptrace_scope` is set to `>= 2` (`admin-only` `ptrace`) or `AppArmor`/`SELinux` isolates user apps, a compromised browser extension or `npm` postinstall script running under `UID 1000` could attempt to inspect or tamper with a concurrent `--empower` process in the same user session!

Third, brokered privilege is only as trustworthy as its IPC authentication and authorization daemon (`polkitd` evaluating `/etc/polkit-1/rules.d/*.rules` [333] and `D-Bus` / `Varlink` peer credential lookup). If the message bus or authorization daemon suffers a Time-of-Check to Time-of-Use (`TOCTOU`) PID-reuse or disconnect race when identifying *which* client process sent an IPC request (as Kevin Backhouse famously exploited in `Polkit` `CVE-2021-3560` by disconnecting `dbus-send` mid-call so `polkitd`'s `/proc/<pid>` UID lookup failed open into `UID 0` authorization!), brokered elevation collapses without a single `SUID` binary on disk. How `systemd`, `D-Bus`, and brokerless `Varlink` confine persistent system services and bind peer identity race-freely using kernel `pidfd` descriptors (`SO_PEERPIDFD`) is the exact subject of [Chapter 11](11-systemd-dbus-sandboxing.md).

## Inspecting on a Live Linux Host

Operational verification enumerates residual `SUID`/`SGID` inodes on `/usr`, confirms `run0`'s unprivileged `0755` permissions and `TIOCSTI` kernel disablement, and audits `sudo` patch levels (`>= 1.9.17p1` or `sudo-rs`) plus `nosuid` mount posture.

Audit every remaining `SUID` (`-4000`) and `SGID` (`-2000`) binary on `/usr` (hardened container images and `nosuid` server profiles aim for zero results):

```bash
find /usr/bin /usr/sbin /usr/libexec -perm /6000 -printf "%m %u:%g %p\n" 2>/dev/null | sort | head -n 15
```

Representative output on a minimal modern Linux host:

```text
2755 root:tty /usr/bin/wall
4755 root:root /usr/bin/fusermount3
4755 root:root /usr/bin/passwd
```

Verify that `run0` is a normal unprivileged symlink (`0755` on `systemd-run`, zero `s` bit) and confirm that legacy `TIOCSTI` terminal byte injection is disabled in Ring 0:

```bash
ls -la $(command -v run0 2>/dev/null) $(command -v systemd-run 2>/dev/null) 2>/dev/null
sysctl dev.tty.legacy_tiocsti 2>/dev/null || true
```

Expected output on `Linux 6.2+` with `systemd v256+`:

```text
lrwxrwxrwx 1 root root      11 Oct 12 00:00 /usr/bin/run0 -> systemd-run
-rwxr-xr-x 1 root root  108840 Oct 12 00:00 /usr/bin/systemd-run
dev.tty.legacy_tiocsti = 0
```

Check whether legacy `sudo` (if installed) is patched past `CVE-2025-32462` / `CVE-2025-32463` (`>= 1.9.17p1` or `sudo-rs`), enforces `use_pty`, and which mounts enforce `nosuid`:

```bash
sudo --version 2>/dev/null | head -n 2 || true
findmnt -o TARGET,FSTYPE,OPTIONS | grep -E "TARGET|nosuid" | head -n 10
```

Audit `NoNewPrivileges` and `RestrictSUIDSGID` posture across active `systemd` services and verify Polkit rules governing `run0` (`org.freedesktop.systemd1.manage-units` and `empower` group authorization [329, 333]):

```bash
systemctl show -p NoNewPrivileges,RestrictSUIDSGID sshd.service systemd-journald.service 2>/dev/null
ls -1 /usr/share/polkit-1/rules.d/ /etc/polkit-1/rules.d/ 2>/dev/null | head -n 10
```

Representative output confirming `NoNewPrivileges=yes` and `RestrictSUIDSGID=yes` on core system units alongside declarative Polkit rule directories:

```text
NoNewPrivileges=yes
RestrictSUIDSGID=yes

NoNewPrivileges=no
RestrictSUIDSGID=no
50-default.rules
systemd-networkd.rules
```

Services reporting `NoNewPrivileges=yes` and `RestrictSUIDSGID=yes` can neither create `04000` files on disk nor gain credentials across `execve(2)`, ensuring that even a full remote code execution bug inside the daemon finds zero usable `SUID` escalation targets on the host.

