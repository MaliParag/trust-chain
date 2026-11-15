#!/usr/bin/env python3
"""Extra Batch 4 diagram generator for Volume III (The Linux Trust Chain, Chapters 16-20).

Generates 5 collision- and orthogonality-verified SVG diagrams into books/linux/src/diagrams/:
- 16-extra-spire-node-and-workload-attestation.svg
- 17-extra-git-hook-escape-vs-ro-mask.svg
- 18-extra-coconut-svsm-vmpl0-vtpm.svg
- 19-extra-kata-rego-policy-gate.svg
- 20-extra-ifunc-linkmap-rsa-hook.svg
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
from diagram_lib import (
    build_fan_bands,
    build_sequence,
    build_split_domains,
    build_vertical_flow,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def P(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def generate_batch4_extras():
    # 16-extra: Multi-substrate SPIRE Node + Kernel Workload Attestation & Bundle Federation
    build_fan_bands(
        P("16-extra-spire-node-and-workload-attestation.svg"),
        "SPIFFE/SPIRE Hardware Node Roots, Kernel Selectors, and Bundle Federation",
        [
            [
                {
                    "id": "server",
                    "tag": "Trust Domain Control Plane & Cross-Cluster Federation",
                    "title": "SPIRE Server Authenticates Nodes (tpm_devid, aws_iid, gcp_iit, k8s_psat) and Federates Bundles",
                    "body": "Enforces Trust-On-First-Attest (TOFA), scopes authorized registration entries per node, and exchanges CA bundles via https_spiffe",
                    "theme": "purple",
                }
            ],
            [
                {
                    "id": "att_tpm",
                    "tag": "Hardware Node Root",
                    "title": "TPM 2.0 DevID (tpm_devid)",
                    "body": "IEEE 802.1AR factory IDevID cert + TPM2_Certify prove physical silicon residency",
                    "theme": "slate",
                },
                {
                    "id": "att_unix",
                    "tag": "Kernel Process Attester",
                    "title": "SO_PEERCRED + SO_PEERPIDFD",
                    "body": "Unforgeable socket peer check over UID, GID, and /proc/pid/exe SHA-256 digest",
                    "theme": "teal",
                },
                {
                    "id": "att_k8s",
                    "tag": "Cgroup & Pod Attester",
                    "title": "cgroups v2 & Kubelet Verify",
                    "body": "Maps caller cgroup slice to systemd unit or K8s Pod UID, SA, and image SHA-256",
                    "theme": "green",
                },
            ],
            [
                {
                    "id": "svid",
                    "tag": "Workload API Over /run/spire/sockets/agent.sock (Zero Static Secrets on Disk)",
                    "title": "Auto-Rotated 1-Hour X.509-SVID (mTLS URI SAN) + Audience-Bound JWT-SVID + Federated Bundles",
                    "body": "Streamed directly into Envoy, Cilium, or app RAM via gRPC; rotates keys and cross-cloud root CAs without restarting processes",
                    "theme": "green",
                }
            ],
        ],
        [
            ("server", "att_tpm", "attests silicon", "purple", False),
            ("server", "att_unix", "pushes selectors", "teal", False),
            ("server", "att_k8s", "scopes pod entries", "green", False),
            ("att_tpm", "svid", "Agent SVID root", "slate", False),
            ("att_unix", "svid", "verifies binary", "teal", False),
            ("att_k8s", "svid", "mints pod SVID", "green", False),
        ],
        footer="Combining hardware/cloud node attestation with kernel pidfd and cgroup v2 workload attestation eliminates bootstrap secrets.",
    )

    # 17-extra: Persistent .git/hooks & .git/config Escape vs Read-Only Subpath Masking
    build_split_domains(
        P("17-extra-git-hook-escape-vs-ro-mask.svg"),
        "Defeating .git/hooks and Config Persistence Escapes with Read-Only Bind Masks",
        left={
            "label": "Naive Workspace-Scoped Agent",
            "theme": "red",
            "cards": [
                {
                    "tag": "Untrusted Input",
                    "title": "XPIA in PR Diff, README, or MCP Output",
                    "body": "Adversarial tokens instruct coding agent to write helper script inside ./repo",
                    "theme": "white",
                },
                {
                    "tag": "Control-Plane Tampering",
                    "title": "Mutates .git/hooks or .git/config",
                    "body": "Writes .git/hooks/pre-commit, core.fsmonitor, or .vscode/settings.json autoApprove",
                    "theme": "white",
                    "in_edge": "allowed inside ./repo",
                },
                {
                    "tag": "Delayed Host Escape",
                    "title": "Executes Unsandboxed on Host git status",
                    "body": "Developer runs git on host terminal; hook steals ~/.ssh and cloud credentials",
                    "theme": "white",
                    "in_edge": "escapes sandbox",
                },
            ],
        },
        right={
            "label": "Hardened Bubblewrap + Landlock Mask",
            "theme": "green",
            "cards": [
                {
                    "tag": "Base Isolation",
                    "title": "Read-Only Root + Writable ./repo Bind",
                    "body": "--ro-bind / / with --bind ./repo /workspace unmaps host $HOME completely",
                    "theme": "white",
                },
                {
                    "tag": "Surgical Carveouts",
                    "title": "Read-Only Masks Over Executable Paths",
                    "body": "Stacks --ro-bind on .git/hooks, .git/config, .vscode, .codex & /dev/null on symlinks",
                    "theme": "white",
                    "in_edge": "specificity mount order",
                },
                {
                    "tag": "Deterministic Kernel Deny",
                    "title": "Ring 0 VFS Returns -EROFS Immediately",
                    "body": "Agent edits source & commits objects normally, while hook/config writes fail in VFS",
                    "theme": "white",
                    "in_edge": "blocks persistence",
                },
            ],
        },
        bridges=[
            (0, 0, "lr", "mounts fresh VFS", "teal"),
            (1, 1, "lr", "masks .git control files", "green"),
            (2, 2, "lr", "neutralizes host trigger", "purple"),
        ],
        boundary_label="VFS Subpath Mount Policy",
        footer="Writable access to a Git working tree is equivalent to host code execution unless .git/hooks, .git/config, and IDE configs are masked read-only.",
    )

    # 18-extra: COCONUT-SVSM VMPL0 Paravisor & Enclave vTPM Protocol
    build_sequence(
        P("18-extra-coconut-svsm-vmpl0-vtpm.svg"),
        "COCONUT-SVSM Intra-Enclave VMPL0 Isolation, CAA Protocol, and Measured vTPM",
        [
            {"title": "Untrusted Host KVM", "sub": "Cloud Hypervisor (C=0 Only)", "theme": "amber"},
            {"title": "VMPL1 Guest Linux", "sub": "OVMF + Signed UKI + LUKS2", "theme": "slate"},
            {"title": "VMPL0 COCONUT-SVSM", "sub": "Rust Paravisor + libtpms vTPM", "theme": "purple"},
            {"title": "SEV-SNP Silicon & RMP", "sub": "ASP + AES-XTS + RMP Table", "theme": "teal"},
        ],
        [
            (0, 3, "SNP_LAUNCH_UPDATE + FINISH measures SVSM + OVMF into LAUNCH_DIGEST", "amber", False),
            (2, 3, "RMPADJUST strips VMPL1..3 R/W/X permissions from VMPL0 RAM pages", "purple", False),
            (1, 2, "Trap via SVSM Calling Area (CAA): SVSM_CORE_PVALIDATE page accept", "slate", False),
            (2, 3, "Execute PVALIDATE in VMPL0 and enforce Restricted/Alternate Injection", "teal", False),
            (1, 2, "systemd-stub / tpmrm0 sends SVSM_VTPM_CMD (PCR_Extend / Unseal)", "slate", False),
            (2, 2, "Evaluate PCR[11] policy inside isolated VMPL0 libtpms RAM", "purple", False),
            (2, 1, "Return unsealed LUKS2 volume key without crossing to host KVM", "green", False),
        ],
        boundary_after=0,
        boundary_label="Host VMM / Hardware-Encrypted Guest",
        footer="Even a full Ring 0 compromise of the VMPL1 guest Linux kernel cannot read or forge VMPL0 COCONUT-SVSM vTPM secrets.",
    )

    # 19-extra: Closing the Kubelet Confused-Deputy Backdoor with Kata agent-policy.rego
    build_vertical_flow(
        P("19-extra-kata-rego-policy-gate.svg"),
        "Closing the Kubelet Backdoor Inside Confidential Containers with agent-policy.rego",
        [
            {
                "tag": "Step 1 · Workload Owner CI Build",
                "title": "genpolicy Compiles Strict OPA Rego Policy Into initdata.toml",
                "body": "Pins allowed container SHA-256 digests, argv, env, CopyFileRequest=false, ReadStreamRequest=false, and ExecProcessRequest=false",
                "theme": "slate",
            },
            {
                "tag": "Step 2 · Silicon Launch Commitment",
                "title": "SHA-384(initdata) Bound Into SEV-SNP HOST_DATA or TDX MRCONFIGID",
                "body": "Attestation Agent verifies received initdata matches hardware launch register before loading policy.rego into kata-agent",
                "theme": "purple",
                "edge_label": "measured at VM boot",
            },
            {
                "tag": "Step 3 · Intra-Enclave ttRPC Reference Monitor",
                "title": "kata-agent Rego Engine Evaluates Every Host Shim Request Over AF_VSOCK",
                "body": "Admits matching CreateContainerRequest while deterministically rejecting unauthorized exec, mount, or stream calls",
                "theme": "teal",
                "edge_label": "loads immutable Rego",
            },
            {
                "tag": "Step 4 · RCAR Attestation & Key Release",
                "title": "Trustee KBS Verifies Quote + Initdata Digest Before Releasing ocicrypt Keys",
                "body": "If host kubelet alters policy.rego to re-enable kubectl exec, HOST_DATA changes and Trustee withholds workload secrets",
                "theme": "green",
                "edge_label": "quote binds HOST_DATA",
            },
        ],
        side_notes={
            2: {
                "tag": "Host Attack Blocked",
                "title": "Compromised Worker Kubelet",
                "body": "Attempts kubectl exec, rogue bind-mount, or LD_PRELOAD injection; rejected inside TEE with PermissionDenied",
                "theme": "red",
                "reverse": True,
                "edge_label": "blocked RPC",
            },
        },
        footer="Binding policy.rego into hardware HOST_DATA/MRCONFIGID strips a compromised Kubernetes node of interactive pod control.",
    )

    # 20-extra: In-Memory Dynamic Linker Hijack in XZ Utils (IFUNC -> link_map -> RSA_public_decrypt)
    build_vertical_flow(
        P("20-extra-ifunc-linkmap-rsa-hook.svg"),
        "In-Memory Dynamic Linker Hijack Inside sshd (XZ Utils CVE-2024-3094 Stage 4)",
        [
            {
                "tag": "Phase 1 · Early Relocation Window (-Wl,-z,now)",
                "title": "ld.so Loads sshd -> libsystemd.so.0 -> liblzma.so.5.6.1 Before RELRO Locks GOT",
                "body": "Full RELRO marks the Global Offset Table read-only only AFTER early symbol and STT_GNU_IFUNC resolution completes",
                "theme": "slate",
            },
            {
                "tag": "Phase 2 · Indirect Function Trigger",
                "title": "crc32_resolve() & crc64_resolve() Invoke Injected _get_cpuid() Resolver",
                "body": "Verifies argv[0] == /usr/sbin/sshd via trie hashes and aborts silently if TERM, LD_DEBUG, LD_PROFILE, or gdb/rr is present",
                "theme": "amber",
                "edge_label": "executes before main()",
            },
            {
                "tag": "Phase 3 · Linker Audit Hook & PLT/GOT Redirection",
                "title": "Walks _r_debug link_map & Installs Temporary _dl_audit_symbind_alt Hook",
                "body": "Intercepts resolution of OpenSSL RSA_public_decrypt (and EVP_PKEY_set1_RSA), redirecting sshd GOT pointer to implant",
                "theme": "purple",
                "edge_label": "mutates writable GOT",
            },
            {
                "tag": "Phase 4 · Asymmetric Pre-Auth Command Execution",
                "title": "Extracts ChaCha20-Encrypted Payload From SSH RSA Modulus & Verifies Ed448 Sig",
                "body": "Valid Ed448 signature executes attacker payload via system() as unsandboxed UID 0 prior to SSH authentication",
                "theme": "red",
                "edge_label": "SSH pubkey packet",
            },
        ],
        side_notes={
            3: {
                "tag": "Stealth Fallback",
                "title": "Normal SSH Clients & Scanners",
                "body": "Non-matching RSA keys pass straight to real libcrypto RSA_public_decrypt with zero crash or auth-log anomaly",
                "theme": "green",
                "edge_label": "invalid tag/sig",
            },
        },
        footer="GNU_IFUNC resolvers execute inside ld.so before PT_GNU_RELRO freezes the GOT, turning a compression helper into an early-boot rootkit.",
    )


def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    generate_batch4_extras()
    print("Successfully generated and collision-verified all 5 Batch 4 extra SVG diagrams!")


if __name__ == "__main__":
    main()
