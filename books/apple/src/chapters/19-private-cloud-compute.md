# Private Cloud Compute and Verifiable Cloud Inference

## Overview

* **Link in the Chain:** Verifiable confidential-cloud capstone of Part IV; extends Apple Silicon `Boot ROM`, `Image4`, `SEP` attestation, `SPTM`, and cryptographic transparency logs ([Chapter 1](01-secure-boot.md) through [Chapter 4](04-silicon-memory-safety.md), [Chapter 12](12-sep-app-device-attestation.md), [Chapter 16](16-imessage-pq3-kt.md)) into Apple data centers for cloud AI inference (`PrivateCloudComputeLanguageModel`).
* **Core Security Invariant:** A user device encrypts prompt tokens via `HPKE` exclusively to ephemeral `SEP`-attested keys belonging to stateless Apple Silicon `PCC` server nodes whose exact `Image4` OS, model, and configuration digests are pre-committed inside a public append-only Transparency Log, routed through a third-party `Oblivious HTTP` (`OHTTP`) relay that decouples client IP from payload.
* **Platform Matrix:** Client-side `PCC` verification, `OHTTP` blinding, and `PrivateCloudComputeLanguageModel` APIs (`WWDC26`) run across `iOS` (`18.1+`/`26+`), `iPadOS`, `macOS` (`15.1+`/`26+`, including the `fm` CLI), and `visionOS`, talking to custom headless Apple Silicon server blades running hardened `pccOS`.
* **Trusted Computing Base (TCB):** Custom Apple Silicon `PCC` server SoCs (`Boot ROM`, `SEP`, `SPTM`, `TXM`, encrypted ephemeral RAM without persistent storage), the `pccOS` `Image4` software stack audited via the public Transparency Log, non-collusion between the third-party `OHTTP` relay and Apple, and external security researchers inspecting published `PCC` releases.
* **Failure Horizon & Handoff:** Compromising a signed `pccOS` parser before Transparency Log revocation, side-channel leakage if hardware physical security at the data center were breached alongside `SEP`, or user-authorized handoff to third-party cloud models (`ChatGPT` integration, which explicitly leaves `PCC` boundaries after user consent); leads into the end-to-end failure and legal compulsion synthesis in [Chapter 20](20-mercenary-chains-compulsion.md).

## Threat Model & Design Tension

For decades, every cloud AI and SaaS provider offered consumers the same contractual promise: *"Your requests are encrypted in transit with TLS 1.3, processed inside our secure servers, and our privacy policy says we won't log or train on your prompts."* From a systems-security perspective, TLS termination at a cloud load balancer places the *entire cloud infrastructure, every site-reliability engineer (`SRE`) with production SSH/debug access, every crash-dump collector, every telemetry pipeline, and every secret government wiretap warrant squarely inside the user's Trusted Computing Base (`TCB`)* [2]! Once TLS terminates at the ingress proxy, plaintext user emails, medical notes, source code, and personal reflections traverse internal microservice meshes where a single misconfigured debug logger, compromised admin laptop, or targeted subpoena (`IPA` Section 253 or `FISA` order) can silently copy one user's prompts without leaving a single client-observable trace.

Even standard enterprise *Confidential Computing* (`AMD SEV-SNP`, `Intel TDX`, and `NVIDIA H100` Confidential GPU enclaves powering `Azure Confidential VMs`), while transformative for enterprise IaaS tenants, was engineered for a *tenant-versus-cloud-provider* threat model rather than a *consumer-versus-first-party-service* model [2]: in an enterprise CVM, the corporate tenant controls the guest OS image, SSH keys, persistent encrypted disks, and observability agents. When *Apple itself* operates the consumer AI service (`Apple Intelligence` and `WWDC26`'s `PrivateCloudComputeLanguageModel` for 32K-token reasoning [2, 130]), hardware memory encryption alone proves nothing if Apple could simply sign and deploy a second, secret "logging-enabled" `pccOS` image routed selectively to a targeted journalist's IP address!

To extend the `iPhone`'s vendor-excluding TCB into the cloud, Apple SEAR defined five hard architectural requirements for *Private Cloud Compute (`PCC`)* [2]: *Stateless Computation* (prompts never touch non-volatile storage and vanish immediately after response), *Enforceable Guarantees* (anchored in `SEP` and `SPTM`), *No Privileged Runtime Access* (no operator shell or payload debugging exists in production), *Non-Targetability* (the `PCC` cluster cannot tell which user or IP sent a request, preventing targeted single-user subversions), and *Verifiable Transparency* (client devices mathematically refuse to talk to any server binary that has not been published to a global cryptographic Transparency Log for independent inspection by outside researchers!).

## Silicon & System Mechanics

### Stateless Custom Apple Silicon Blades and Hardened pccOS

Rather than renting commodity x86/GPU racks, Apple designed custom server blades powered by `M`-series Apple Silicon SoCs (`M2 Ultra` in Gen-1 `PCC`, scaling across newer Apple Silicon server generations) preserving the exact hardware trust anchors analyzed in Part I (`Boot ROM`, `Image4`, `AppleDART`, `SEP` with inline DRAM encryption, `SPTM` in `GL2`, `TXM` in `GL0`, and hardware memory safety) [1, 2, 5].

Crucially, `PCC` server nodes are manufactured *physically without persistent NVMe storage volumes for runtime state* [2]. At boot, the node fetches its `pccOS` image (`iOS`/`macOS`-derived stripped Darwin variant), model weights, and `Image4` manifests (`IM4P`/`IM4M`), verifying every component down to `Boot ROM` and sealing the entire read-only runtime filesystem in RAM under `APFS` `SSV` semantics ([Chapter 5](05-apfs-ssv-dyld.md)) [2, 56]. Immediately upon boot, the `PCC` node generates a random, purely ephemeral RAM encryption key that never leaves volatile silicon; power-cycling the blade cryptographically vaporizes every page of server DRAM!

To uphold *No Privileged Runtime Access*, production `pccOS` strips all remote login daemons (`sshd`), interactive shells, dynamic task-inspection/debugging interfaces (`task_for_pid`), and general-purpose diagnostic tools at build time (`TXM` Static Trust Cache contains *only* the minimal inference, attestation, and stripped metric daemons; zero Dynamic Trust Caches can be loaded post-boot!) [2, 64]. Even crash logs, stack traces, and performance metrics are filtered through strict static allowlists (`os_log` privacy enforcement with raw payload buffers excluded from telemetry pipelines) so an induced crash inside the inference engine cannot exfiltrate user tokens into an SRE monitoring dashboard [2].

### OHTTP Blind Relays, Anonymous Rate-Limiting, and SEP Ephemeral HPKE

How does a user's `iPhone` send a prompt to `PCC` such that `PCC` cannot target a specific user *and* an eavesdropper cannot read the prompt? `PCC` composes `RFC 9458` *Oblivious HTTP (`OHTTP`)* with end-to-end *Hybrid Public Key Encryption (`HPKE`, `RFC 9180`)* terminating directly inside attested `PCC` compute nodes [2, 133].

![Figure: Private Cloud Compute (PCC) end-to-end request lifecycle combining Transparency Log Image4 verification, third-party OHTTP IP blinding, and stateless SEP-attested node inference.](diagrams/19-pcc-ohttp-attestation-flow.svg)

Follow a single `PrivateCloudComputeLanguageModel` or `Siri` cloud reasoning request step by step [2, 130, 133]:

First, out of band, candidate `PCC` nodes inside Apple data centers generate ephemeral `HPKE` request-decryption keypairs protected by their on-die `SEP` (`SKS` enforces lifecycle limits and prevents key export even if `pccOS` `EL1` were compromised!), publishing bundles of `SEP`-signed node attestation certificates (`x5c` chaining to Apple's `PCC` Attestation CA + `Image4` boot digests + `Transparency Log` inclusion proofs) [2, 107]. Second, before encrypting a single byte of the user's prompt, the *client `iPhone` or `Mac` itself* verifies a multi-predicate cryptographic gate locally:

$$\text{AdmitNode}(N) \iff \text{VerifySEP}(\texttt{x5c}_N) \;\land\; \text{VerifyLogInclusion}\bigl(\texttt{IM4M}_N,\, \text{STH}_{\text{PCC-Log}}\bigr)$$

If *any* component hash reported by the `PCC` node's `SEP` attestation (`iBoot`, `pccOS` `SSV` seal, `SPTM`, `TXM`, model runtime configuration) is absent from the verified public Transparency Log (`STH`), the client aborts immediately without transmitting the prompt [2]!

Third, to prevent denial-of-service abuse without revealing *which* Apple Account is calling `PCC`, the client presents an unlinkable *Privacy Pass / Rate-Limited Anonymous Access Token* (blindly signed during an earlier authenticated `AuthKit` session so redemption proves *"this comes from a valid rate-limited Apple Silicon device"* with zero linkability back to the user's Apple ID!) [2]. Fourth, the client encrypts the prompt via `HPKE` directly to the chosen `PCC` node set's `SEP`-bound public key (`inner HPKE`), wraps that ciphertext + target gateway hint inside an outer `OHTTP` encryption layer (`outer HPKE`), and sends it over TLS to an *independent third-party `OHTTP` Relay* (operated by an external network partner such as Fastly/Cloudflare rather than Apple!) [2, 133].

Observe the strict information partition across the hop [2, 133]:
The *Third-Party `OHTTP` Relay* sees the client's source IP address (`TCP`/`TLS`), strips the IP, unwraps only the routing metadata, and forwards the opaque inner `HPKE` ciphertext to Apple's `PCC` Gateway; the relay *never* sees the prompt or model response. Conversely, Apple's *`PCC` Gateway and Compute Node* see the inner `HPKE` ciphertext (unwrapped exclusively inside the attested `PCC` node's memory to run `MLX`/Transformer inference, encrypt the response back to the client's ephemeral response key, and zeroize the request arena immediately upon completion), while *never* seeing the user's IP address or Apple Account! Consequently, even if a hostile state actor physically walked into an Apple `PCC` data center demanding *"wiretap prompts coming from Journalist X,"* `PCC` ingress possesses *zero user identifier or IP address on which to trigger selective targeting* [2]!

### Public Transparency Log and Virtual Research Environment (VRE)

Wait: what stops Apple from adding a backdoor to the official `pccOS` build *and* publishing its hash to the Transparency Log, hoping nobody notices? Apple closes that loop by publishing the actual *inspectable `pccOS` binary images* alongside every production Transparency Log entry, paired with a `macOS` *Virtual Research Environment (`VRE`)* shipped natively inside `macOS Sequoia 15.1+` / `Tahoe 26` (`pccvre` CLI tool running atop `Virtualization.framework`!) and open-source build/subset audit code [2]! Any independent security researcher on earth can pull every production `PCC` release logged in the Transparency Log, verify its `Image4` hashes match the exact digests their own personal `iPhone` trusts, boot `pccOS` locally inside `pccvre` on a Mac, disassemble every binary, and verify that zero prompt-exfiltration or persistent logging paths exist (backed by up to $1,000,000 bug bounties in the Apple Security Bounty program) [2].

## Platform Forks Across Apple OSes

Across `iOS`, `iPadOS`, `macOS`, and `visionOS` (`watchOS` delegates heavy cloud intelligence via `iPhone` or bounded endpoints), the client-side `PCC` verifier (`PrivateCloudCompute` / `FoundationModels` `PrivateCloudComputeLanguageModel` exposed to third-party app developers at `WWDC26` so apps can run 32K-context reasoning models on `PCC` at zero developer server cost and zero developer visibility into Apple's cloud! [8, 130]) enforces identical `OHTTP` + Transparency Log invariants. Crucially, when a user opts into an *external* third-party model integration (such as Siri's optional handoff to OpenAI's `ChatGPT`), `iOS`/`macOS` displays an explicit UI boundary/consent prompt because requests crossing into external clouds leave `PCC`'s hardware/Transparency-Log guarantees and become governed by the external provider's zero-retention contractual terms instead [1, 2].

![Figure: Architectural comparison matrix contrasting Apple Private Cloud Compute (stateless custom silicon, mandatory OHTTP IP blinding, and public binary Transparency Logs) against enterprise Azure Confidential VMs and traditional TLS GPU clouds.](diagrams/19-pcc-vs-cvm-comparison.svg)

Comparing `PCC` against enterprise `Confidential VMs` (`Azure CVM` on `AMD SEV-SNP` / `Intel TDX` or `Google Private AI Compute`) clarifies *why* both architectures look different despite solving confidential inference [2]. Enterprise `CVM`s give a corporate customer (`Contoso`) isolated encrypted memory, virtual encrypted disks, and tenant SSH access inside `Microsoft`'s cloud so `Contoso` excludes `Microsoft`, while `Contoso`'s own admins remain fully inside `Contoso`'s TCB! `PCC` solves the strictly harder consumer problem where *the operator running the model (`Apple`) must exclude itself* from millions of end users' TCBs simultaneously, necessitating stateless diskless nodes, disabled operator shells, `OHTTP` non-targetability, and globally published binary builds [2].

## In-the-Wild Failures & Architectural Bounds

| Case / Mechanism | Year | Platform Scope | Boundary Tested | Root Cause | Architectural Response |
|---|---|---|---|---|---|
| Pre-Inference Prompt Injection via `.PrivateCloudComputeLanguageModel` | 2026 | `iOS` / `macOS` (`WWDC26` 3P apps) | App-level tool invocation post-`PCC` | `PCC` protects prompt confidentiality *in the cloud*, but if an app feeds untrusted web text into a `PCC` reasoning session wired to local tools, the *returned* tool call still executes locally! | Apply the exact same `.historyTransform` & `.onToolCall` guards ([Chapter 18](18-agentic-ai-workload-isolation.md)) to `PCC` sessions [7, 130] |
| Supply-Chain / Delayed Audit Window in Transparency Log | Theoretical | `PCC` Transparency Log | Pre-rollout public audit latency | If client devices accepted a newly logged `pccOS` build milliseconds after log append before external researchers downloaded it, a brief window could exist | Enforced multi-day/staged rollout delay between Transparency Log publication + artifact availability and production client trust [2] |
| Token-Length / Timing Traffic Analysis at `OHTTP` Edge | Theoretical | `OHTTP` / WAN | Coarse packet-size metadata | Standard `OHTTP` hides IP from `PCC` and payload from Relay, unless request/response byte lengths leak coarse prompt sizes | Fixed-bucket `OHTTP` padding and batched chunking on `PCC` frames [2, 133] |

## Verification & Forensic Artifacts

On `macOS` (`15.1+` / `26+`), Apple ships both the *Apple Intelligence Report* exporter (*System Settings $\to$ Privacy & Security $\to$ Apple Intelligence Report*, allowing any user to export a biometric-unlocked JSON/PDF audit log of every `PCC` request sent in the past 15 minutes or 7 days, including exact attested `PCC` node `Image4` hashes!) and the `pccvre` Virtual Research Environment CLI tool for auditing published `PCC` Transparency Log releases [2]:

```bash
which pccvre >/dev/null 2>&1 && pccvre release list --limit 3 2>/dev/null || ls -la /System/Library/SecurityResearch/ 2>/dev/null || true
```

Observe live `Private Cloud Compute` client attestation, `OHTTP` relay selection, and Transparency Log (`transparencyd` `KT`/`PCC` trees) verification on `macOS` via Unified Logging [2, 90]:

```bash
log show --last 1h --predicate 'subsystem CONTAINS "PrivateCloudCompute" OR subsystem == "com.apple.Transparency"' --style compact | tail -n 5
```

From mask `Boot ROM` in [Chapter 1](01-secure-boot.md) to stateless `PCC` blades in [Chapter 19](19-private-cloud-compute.md), we have derived the complete 20-chapter Apple trust chain. In our Finale, [Chapter 20](20-mercenary-chains-compulsion.md), we step back to synthesize what happens when the world's best-funded adversaries and sovereign legislatures test this vertical edifice at full force, and why it still snaps.
