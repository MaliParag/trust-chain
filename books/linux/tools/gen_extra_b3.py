#!/usr/bin/env python3
"""Extra diagram generator for Batch 3 (Chapters 11-15) of The Linux Trust Chain (Volume III).

Generates 5 collision- and orthogonality-verified architectural SVG diagrams:
- 11-extra-cve-2021-3560-dbus-race.svg
- 12-extra-host-plus-tpm2-hybrid-seal.svg
- 13-extra-openssh-98-binary-split.svg
- 14-extra-cgroup-release-agent-escape.svg
- 15-extra-gvisor-systrap-vs-firecracker-jailer.svg
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
from diagram_lib import (
    build_fan_bands,
    build_horizontal_pipeline,
    build_sequence,
    build_split_domains,
    build_vertical_flow,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def P(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def generate_batch3_extras():
    # 1. Chapter 11: 11-extra-cve-2021-3560-dbus-race.svg
    build_sequence(
        P("11-extra-cve-2021-3560-dbus-race.svg"),
        "CVE-2021-3560: Polkit & AccountsService D-Bus Disconnect UID-0 Race",
        [
            {"title": "Attacker Client", "sub": "dbus-send (UID 1000)", "theme": "red"},
            {"title": "dbus-daemon", "sub": "/run/dbus/system_bus_socket", "theme": "slate"},
            {"title": "AccountsService", "sub": "org.freedesktop.Accounts", "theme": "amber"},
            {"title": "polkitd", "sub": "Polkit Authority (UID 0Check)", "theme": "purple"},
        ],
        [
            (0, 1, "1. Connect & send CreateUser('secadmin', wheel)", "red", False),
            (1, 2, "2. Forward method call from unique bus name :1.92", "slate", False),
            (0, 1, "3. SIGKILL (~5 ms later): close socket & drop :1.92", "red", True),
            (2, 3, "4. CheckAuthorization(system-bus-name ':1.92')", "amber", False),
            (3, 1, "5. GetConnectionUnixUser(':1.92') lookup", "purple", False),
            (1, 3, "6. Error: org.freedesktop.DBus.Error.NameHasNoOwner", "red", True),
            (3, 3, "7. Bug: ignores error bool; stack *out_uid stays 0 (root)!", "red", False),
            (3, 2, "8. Authorized == TRUE (UID 0 skips admin password)", "red", False),
            (2, 2, "9. Writes wheel admin user & hash to /etc/shadow", "red", False),
        ],
        boundary_after=0,
        boundary_label="AF_UNIX IPC Trust Seam",
        bottom_note={
            "tag": "Architectural Cure",
            "title": "Bind Authorization to SO_PEERCRED + SO_PEERPIDFD / Brokerless Varlink Sockets",
            "body": "Propagate D-Bus errors strictly, pin caller identity with kernel pidfd handles at connect(), or eliminate bus intermediaries via Varlink.",
            "theme": "green",
        },
        footer="Numeric PIDs and ephemeral bus names (:1.92) vanish on disconnect; kernel-captured SO_PEERCRED and SO_PEERPIDFD never alias UID 0.",
    )

    # 2. Chapter 12: 12-extra-host-plus-tpm2-hybrid-seal.svg
    build_fan_bands(
        P("12-extra-host-plus-tpm2-hybrid-seal.svg"),
        "systemd-creds Hybrid Sealing (host+tpm2) and Non-Swappable ramfs Projection",
        [
            [
                {
                    "id": "host_key",
                    "tag": "Factor 1 · Persistent Disk Secret",
                    "title": "256-Bit .host Key (/var/lib/systemd/credential.secret)",
                    "body": "Stored mode 0400 on LUKS2 /var; defeats passive SPI/LPC TPM bus interposers when disk remains locked",
                    "theme": "slate",
                },
                {
                    "id": "tpm_key",
                    "tag": "Factor 2 · Silicon Boot Binding",
                    "title": "TPM 2.0 SRK Policy Key (PCR[7] + PCR[11] / pcrlock)",
                    "body": "Unsealed inside TPM 2.0 only under verified Secure Boot + UKI phase; defeats offline disk & backup theft",
                    "theme": "purple",
                },
            ],
            [
                {
                    "id": "aead_wrap",
                    "tag": "Cryptographic Envelope · systemd-creds encrypt --with-key=host+tpm2",
                    "title": "SHA-256 Hybrid Key Derivation -> AES-256-GCM Ciphertext + Authenticated Metadata (AAD)",
                    "body": "Binds logical credential name (e.g., 'db-pass') and monotonic notAfter timestamp in GCM AAD to prevent credential-swapping",
                    "theme": "teal",
                }
            ],
            [
                {
                    "id": "ramfs_out",
                    "tag": "Activation-Time Delivery · LoadCredentialEncrypted=",
                    "title": "PID 1 Unseals Into Private Per-Unit ramfs (/run/credentials/<unit>/, MS_NOSYMFOLLOW | MS_NOEXEC)",
                    "body": "Mode 0400 owned by transient DynamicUser; ramfs pages are kernel-unswappable (never touch swap) and purged on unit stop",
                    "theme": "green",
                }
            ],
        ],
        [
            ("host_key", "aead_wrap", "256-bit host half", "slate", False),
            ("tpm_key", "aead_wrap", "TPM2 PCR-gated half", "purple", False),
            ("aead_wrap", "ramfs_out", "GCM verify + decrypt", "green", False),
        ],
        footer="Neither a stolen backup archive nor a passive discrete-TPM bus tap suffices alone to recover a host+tpm2 service credential.",
    )

    # 3. Chapter 13: 13-extra-openssh-98-binary-split.svg
    build_horizontal_pipeline(
        P("13-extra-openssh-98-binary-split.svg"),
        "OpenSSH 9.8-10.0 Multi-Binary Privilege Separation & Per-Connection ASLR",
        [
            {
                "tag": "Master Daemon",
                "title": "sshd Listener",
                "body": "Accepts TCP 22 & enforces PerSourcePenalties CIDR bans; zero SSHv2 protocol parser",
                "theme": "slate",
            },
            {
                "tag": "OpenSSH 9.8+ Split",
                "title": "sshd-session",
                "body": "Spawned via fresh execve() so stack, heap, and glibc ASLR re-randomize every connection",
                "theme": "teal",
                "edge_label": "execve\n(ASLR)",
            },
            {
                "tag": "OpenSSH 10.0+ Split",
                "title": "sshd-auth Sandbox",
                "body": "chroot('/var/empty') + UID sshd + seccomp-BPF parses KEX/Certs; unloaded after auth",
                "theme": "purple",
                "edge_label": "execve\n(auth)",
            },
            {
                "tag": "Post-Auth Session",
                "title": "User PTY / SSSD",
                "body": "Runs PAM account + session stack, initializes @s keyring & KCM socket, drops to target UID",
                "theme": "green",
                "edge_label": "PAM +\nFIDO2",
            },
        ],
        under_anchor={
            "target_idx": 1,
            "tag": "Neutralized Threat · CVE-2024-6387 (regreSSHion)",
            "title": "Kills fork()-Cloned ASLR Probing & Async-Unsafe SIGALRM Heap Corruption",
            "body": "Replacing fork-only workers with execve('sshd-session') + _exit() signal handlers + PerSourcePenalties blocks 10,000-try heap races.",
            "theme": "red",
            "edge_label": "hardens",
        },
        footer="Splitting listener, pre-auth parser, and session runtime across distinct ELF binaries eliminates shared address-space state before login.",
    )

    # 4. Chapter 14: 14-extra-cgroup-release-agent-escape.svg
    build_vertical_flow(
        P("14-extra-cgroup-release-agent-escape.svg"),
        "Anatomy of the cgroup v1 release_agent Container Escape (CVE-2022-0492)",
        [
            {
                "tag": "Step 1 · Over-Privileged Pod",
                "title": "Mount cgroup v1 Controller & Enable notify_on_release",
                "body": "Container with --privileged (or unshare -UrmC lacking LSM) mounts rdma/memory cgroup v1 and writes 1 to /tmp/cgrp/x/notify_on_release",
                "theme": "amber",
            },
            {
                "tag": "Step 2 · Host Path Discovery",
                "title": "Extract OverlayFS upperdir= Host Path From /etc/mtab",
                "body": "Reads container mount options (upperdir=/var/lib/docker/overlay2/<id>/diff) to learn where container files sit on the host VFS",
                "theme": "amber",
                "edge_label": "leaks host VFS path",
            },
            {
                "tag": "Step 3 · Weaponize Callback",
                "title": "Write $host_path/cmd to release_agent & Empty Child cgroup",
                "body": "Drops root payload at /cmd, registers its host path in release_agent, and exits a dummy sh process inside /tmp/cgrp/x/cgroup.procs",
                "theme": "red",
                "edge_label": "triggers last-task exit",
            },
            {
                "tag": "Step 4 · Ring 0 Confused Deputy",
                "title": "Kernel cgroup1_release_agent Spawns /cmd as Host Root",
                "body": "Workqueue invokes call_usermodehelper() inside init_pid_ns + init_mnt_ns with full CapEff, executing /cmd on the worker node",
                "theme": "red",
                "edge_label": "call_usermodehelper()",
            },
        ],
        side_notes={
            0: {
                "tag": "CVE-2022-0492 Bug",
                "title": "Missing init_user_ns Check",
                "body": "release_agent_write() checked CAP_SYS_ADMIN only after mount, omitting ns_capable(init_user_ns)!",
                "theme": "red",
                "edge_label": "root cause",
            },
            3: {
                "tag": "Structural Fix",
                "title": "Unified cgroups v2",
                "body": "cgroups v2 deletes release_agent completely, replacing upcalls with pollable cgroup.events files!",
                "theme": "green",
                "edge_color": "#2b6a4c",
                "reverse": True,
                "edge_label": "eliminated in v2",
            },
        },
        footer="Kernel upcalls (release_agent, core_pattern, modprobe_path) execute in the root init namespace; cgroups v2 removes upcall helpers by design.",
    )

    # 5. Chapter 15: 15-extra-gvisor-systrap-vs-firecracker-jailer.svg
    build_split_domains(
        P("15-extra-gvisor-systrap-vs-firecracker-jailer.svg"),
        "gVisor Systrap Application Kernel vs. Firecracker Jailed KVM Micro-VM",
        left={
            "label": "gVisor runsc (Systrap Platform)",
            "theme": "teal",
            "cards": [
                {
                    "tag": "Guest Trap · Pure Userspace",
                    "title": "Systrap 7-Byte Binary Hot-Patch (jmp *%gs:offset)",
                    "body": "First syscall triggers SECCOMP_RET_TRAP SIGSYS; Sentry patches mov+syscall into fast shared-memory jump without /dev/kvm",
                    "theme": "white",
                },
                {
                    "tag": "Syscall Engine · Memory-Safe Go",
                    "title": "Go Sentry (vfs2 + netstack) + Separate lisafs Gofer",
                    "body": "Services 250+ Linux syscalls and TCP/IP in bounds-checked Go; proxies container file ops to isolated Gofer over AF_UNIX",
                    "theme": "white",
                    "in_edge": "shared-mem ring",
                },
                {
                    "tag": "Outer Host Cage",
                    "title": "Empty pivot_root + ~68-Syscall Host seccomp-BPF",
                    "body": "Blocks host open/socket creation inside Sentry; host Ring 0 sees only filtered memory/futex/epoll syscalls",
                    "theme": "white",
                    "in_edge": "no direct host open()",
                },
            ],
        },
        right={
            "label": "AWS Firecracker + Jailer VMM",
            "theme": "purple",
            "cards": [
                {
                    "tag": "Guest Trap · Silicon SLAT",
                    "title": "Dedicated Guest Linux Kernel Under VT-x EPT / Stage-2",
                    "body": "Container syscalls terminate inside per-pod guest Ring 0; VMGenID reseeds guest CSPRNG synchronously on snapshot restore",
                    "theme": "white",
                },
                {
                    "tag": "Device Model · ~50k LoC Rust",
                    "title": "Minimalist Rust VMM (virtio-net, virtio-blk, vsock)",
                    "body": "Strips QEMU BIOS/PCI/USB/VGA attack surface; enforces token-bucket IOPS & bandwidth limiters on host TAP/block FDs",
                    "theme": "white",
                    "in_edge": "KVM_RUN VM-EXIT",
                },
                {
                    "tag": "Outer Host Cage",
                    "title": "jailer chroot + Unique UID + Per-Thread VMM seccomp",
                    "body": "Isolates each micro-VM in /srv/jailer, cgroups v2, netns, and ~35-syscall VMM/vCPU/API seccomp filters",
                    "theme": "white",
                    "in_edge": "confined Rust VMM",
                },
            ],
        },
        bridges=[
            (0, 0, "both", "Ring 3 jmp vs. CPU EPT", "slate"),
            (1, 1, "both", "Go ABI vs. Rust VMM", "teal"),
            (2, 2, "both", "strict host seccomp cage", "green"),
        ],
        boundary_label="De-Privileged Isolation Architecture",
        footer="Systrap runs anywhere in userspace without nested KVM; Firecracker delivers native guest kernel compatibility backed by hardware EPT/Stage-2.",
    )


if __name__ == "__main__":
    generate_batch3_extras()
    print("SUCCESS: Generated and collision-verified 5 Batch 3 extra SVG diagrams.")
