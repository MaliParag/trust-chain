# Cloud Workload Identity: OIDC Projections, IMDSv2, and SPIFFE/SPIRE

## Overview

* **Link in the Chain:** Authenticates Linux containers and micro-VMs ([Chapter 14](14-containers-escapes.md) and [Chapter 15](15-gvisor-microvms.md)) to cloud control planes, object stores, and peer microservices without static credentials, rooting ephemeral `X.509` and `JWT` identities in `TPM 2.0` or cloud node attestation and Linux kernel `SO_PEERCRED`, `SO_PEERPIDFD`, and `cgroups v2` inspection.
* **Core Security Invariant:** Workloads never hold long-lived static API secrets (`AWS_SECRET_ACCESS_KEY`) or inherit broad worker-node `IMDSv1` roles; instead, host metadata enforces `IMDSv2` stateful `PUT` tokens with `IP TTL = 1` hop limits, Kubernetes projects short-lived audience- and node-bound OIDC `TokenRequest` JWTs per pod, and `SPIRE` issues auto-rotated `X.509-SVID` mTLS certificates only after verifying node hardware or IID provenance alongside unforgeable kernel peer selectors.
* **Deployment Profile Matrix:** Legacy cloud VMs rely on unhardened instance-wide IAM roles (`169.254.169.254`); modern cloud Kubernetes (`EKS` IRSA and Pod Identity, `GKE` Workload Identity, `AKS` Workload Identity) enforces `HttpTokens=required` plus `HttpPutResponseHopLimit=1` on `IMDSv2` and projects bound OIDC JWTs; hybrid bare-metal and multi-cloud meshes standardize on `CNCF SPIFFE` and `SPIRE` (`Istio`, `Cilium`, `Envoy`).
* **Trusted Computing Base (TCB):** Cloud hypervisor metadata endpoint (`169.254.169.254`), Linux network stack (`TTL` decrement in `ip_forward` and `nftables`/CNI egress filters), Kubernetes `kube-apiserver` OIDC signer plus `kubelet` projected-volume manager, and `SPIRE` Server plus local `SPIRE` Agent (`SO_PEERCRED`/`SO_PEERPIDFD` and `TPM 2.0` `IDevID` or IID node attesters).
* **Integration Seam & Handoff:** Eliminates static cloud credential sprawl and `169.254.169.254` SSRF node-role theft across microservices; hands off specialized workspace confinement and out-of-sandbox credential brokering for prompt-injected AI agents to [Chapter 17](17-ai-agent-sandboxes.md).

## Problem Statement & Threat Model

How does an unprivileged Linux process scheduled onto an ephemeral cloud virtual machine or a multi-tenant Kubernetes worker node prove its cryptographic identity to an external PostgreSQL cluster, an S3 object bucket, or a sibling microservice? For the first decade of public-cloud and container adoption, operational practice oscillated between two structurally broken patterns [462, 463, 464]. The first anti-pattern, *static secret distribution*, minted non-expiring bearer secrets such as `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` pairs, long-lived OAuth2 `client_secret` strings, or multi-year client TLS private keys, and scattered them across CI/CD variables, `.env` files, configuration repositories, and base64-encoded Kubernetes `Secret` manifests in `etcd`. Because those credentials carried neither temporal bounds nor hardware or process residency constraints, a single leaked Git commit, crash dump, readable `etcd` snapshot, or compromised laptop granted an external adversary persistent impersonation authority from anywhere on the internet.

To eliminate static credential files on disk, cloud providers introduced a second pattern, *ambient link-local instance metadata*, exposing dynamic temporary credentials over an unauthenticated HTTP server bound to the IPv4 link-local address `169.254.169.254` (`RFC 3927` [465]), emulated directly by the host hypervisor or Nitro card [81, 462]. Under Instance Metadata Service Version 1 (`IMDSv1`), any process sharing the VM's network reachability could issue a single, stateless, headerless `HTTP GET` request to `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>` and receive a JSON document containing a live `AccessKeyId`, `SecretAccessKey`, and `SessionToken` for the VM's attached IAM instance profile [81, 462].

The catastrophic fragility of ambient `GET`-based link-local metadata became industry-defining in the July 2019 Capital One breach (`United States v. Paige A. Thompson` [466]), alongside hundreds of subsequent cloud intrusions exploiting the identical seam [462]. In the 2019 incident, the attacker needed zero Linux kernel exploits, zero SSH keys, and zero interactive shell execution on the target EC2 instances. Instead, a misconfigured Web Application Firewall (`WAF`) reverse proxy running Apache `httpd` relayed crafted external HTTP requests via Server-Side Request Forgery (`SSRF`) to `http://169.254.169.254/latest/meta-data/iam/security-credentials/ISSRole-WAF` [462, 466]. Because `IMDSv1` required no session state, custom headers, or hop-count proof, the hypervisor returned valid STS credentials for `ISSRole-WAF` in the response body, enabling external `aws s3 sync` exfiltration across roughly 700 S3 buckets [466]. Worse still, on containerized Linux hosts where `net.ipv4.ip_forward = 1` routes packets from pod network namespaces (`CLONE_NEWNET`, [Chapter 14](14-containers-escapes.md)) across `veth` bridges, every unprivileged container pod inherited ambient access to the worker node's `169.254.169.254` IAM role!

Kubernetes's own early workload identity design (`v1.0` through `v1.20`) suffered from an equally severe set of structural flaws documented in `KEP-1205` and `KEP-2799` [464, 467]. Whenever a `ServiceAccount` was created, the `ServiceAccount` token controller automatically generated a persistent `Secret` object (`type: kubernetes.io/service-account-token`) in `etcd` and mounted it at `/var/run/secrets/kubernetes.io/serviceaccount/token` inside every pod using that account. Those legacy JWTs lacked an `exp` expiration timestamp (remaining valid forever until the `ServiceAccount` or `Secret` was manually deleted), lacked an `aud` audience claim (allowing any internal microservice that accepted a pod's JWT for authentication to turn around and replay that exact bearer token against `kube-apiserver`!), and lacked any cryptographic binding to the specific `Pod` UID or Linux worker `Node` where the token was projected [464, 467, 468].

> **Key Principle.**
> Network location (`169.254.169.254` reachability or pod overlay IP) and static filesystem secrets are ambient capabilities, not workload identities. Under an adversary model spanning application-layer `SSRF`, compromised single-tenant pods attempting lateral escalation across shared Linux worker nodes, and hybrid fleets spanning bare-metal data centers alongside AWS, GCP, and Azure, workload authentication must solve what `SPIFFE` architects term the *Bottom Turtle* problem [463]: bootstrapping short-lived, audience-restricted cryptographic credentials from zero pre-shared application secrets by chaining silicon or hypervisor node attestation directly into Ring 0 kernel process and `cgroup` inspection [464, 469, 470].

## Kernel & Userspace Mechanics

### Defeating Metadata SSRF: `IMDSv2` Session Preflights and Linux `IP TTL = 1` Hop Limits

Engineered by AWS in late 2019 in direct response to the `WAF` reverse-proxy and `SSRF` exploitation wave [81, 462, 466], Instance Metadata Service Version 2 (`IMDSv2`) severs ambient credential theft across two orthogonal protocol layers: HTTP statefulness at Layer 7 and Linux kernel IPv4 packet forwarding mechanics at Layer 3.

![Figure: Why stateless IMDSv1 HTTP GET requests fall to web SSRF and routed container packets, and how IMDSv2 (PUT session preflight + IP TTL = 1 hop limit) paired with Kubernetes projected OIDC tokens isolates cloud credentials.](diagrams/16-imdsv1-ssrf-vs-imdsv2.svg)

At Layer 7, setting instance metadata options to `HttpTokens = required` disables `IMDSv1` entirely, causing `169.254.169.254` to reject every unauthenticated `GET` or `HEAD` request with `HTTP 401 Unauthorized` [81]. Before querying any metadata path, a client must execute a session-initiating `HTTP PUT` request to `http://169.254.169.254/latest/api/token` carrying an explicit lifetime header `X-aws-ec2-metadata-token-ttl-seconds` (ranging from `1` to `21600` seconds) [81, 462]. Two subtle protocol checks harden this `PUT` preflight against real-world web vulnerabilities. First, classic URL-fetch `SSRF` sinks (such as image/webhook validators, XML External Entity `XXE` resolvers, PDF HTML renderers, and `HTTP 302` open redirects) can only trigger `GET` or `POST` requests without custom headers; they cannot synthesize an `HTTP PUT` carrying `X-aws-ec2-metadata-token-ttl-seconds`, parse the returned opaque token string, and replay that string inside `X-aws-ec2-metadata-token` on a second `GET` call [462]. Second, the `IMDSv2` endpoint explicitly inspects inbound `PUT` requests for the presence of an `X-Forwarded-For` HTTP header and rejects the request immediately if present [81, 462]: meaning a misconfigured Apache `mod_proxy`, `nginx`, or Envoy reverse proxy of the exact Capital One class fails closed on contact! (Google Cloud's `Metadata-Flavor: Google` header [471] and Microsoft Azure's `Metadata: true` header [472] block simple headerless `GET` and `302`-redirect `SSRF`, though stateless static headers alone cannot stop an `SSRF` primitive that permits arbitrary request-header injection or full container RCE.)

What happens, however, when an adversary moves beyond `GET`-only `SSRF` and achieves arbitrary shell or Python execution inside an unprivileged container pod on the Linux worker node, enabling them to run `curl -X PUT` directly? That threat is neutralized at Layer 3 by `IMDSv2`'s default `HttpPutResponseHopLimit = 1` setting interacting directly with the Linux kernel's IPv4 forwarding path (`net/ipv4/ip_forward.c`) [81, 465]:

```c
/* Conceptual Linux Ring 0 forwarding gate in net/ipv4/ip_forward.c */
if (ip_hdr(skb)->ttl <= 1)
    goto too_many_hops; /* Sends ICMP_TIME_EXCEEDED and kfree_skb(skb)! */
ip_decrease_ttl(ip_hdr(skb));
```

Trace the exact packet trajectory on a containerized EC2 worker node. Processes running in the host's root network namespace (`init_net`, such as `kubelet` or `amazon-ssm-agent`) communicate directly with the primary Elastic Network Interface (`ens5`), so when the hypervisor stamps `IP TTL = 1` onto the HTTP `200 OK` response carrying the `IMDSv2` session token, the packet enters Linux's `ip_local_deliver()` (`NF_INET_LOCAL_IN`) path without traversing `ip_forward()`, arriving intact with `TTL = 1` [81]. By contrast, a Kubernetes pod isolated inside its own network namespace (`CLONE_NEWNET`, [Chapter 14](14-containers-escapes.md)) sits one L3 router hop behind the host namespace across a virtual Ethernet (`veth`) pair or CNI bridge (`cilium_host`, `cali*`, or `cni0`). Even if the container's outbound `PUT` request (`TTL = 64`) reaches `169.254.169.254`, the hypervisor transmits the token-bearing response packet back with `IP TTL = 1`. When the host Linux kernel receives that response and attempts to route it across `ip_forward()` into the pod's `veth` interface, `ip_hdr(skb)->ttl <= 1` triggers immediately: Ring 0 drops the `sk_buff` and emits `ICMP Time Exceeded` before a single byte of the `IMDSv2` token crosses into the container [81]!

Notice the exact host invariants required to keep this Layer 3 hop barrier airtight: never raise `HttpPutResponseHopLimit` to `2` on Kubernetes nodes (a common anti-pattern in legacy IaC templates that restores container access to node IAM roles), forbid untrusted pods from requesting `hostNetwork: true` via Kubernetes `PodSecurity` admission, and backstop `TTL = 1` with host `nftables` or CNI egress rules dropping `169.254.169.254/32` from pod CIDRs so NAT/mangle rules cannot rewrite packet TTLs [81, 473].

### Bound Projected ServiceAccount Tokens (`KEP-1205`, `KEP-4193`) and Cloud OIDC Federation

Once pods are severed from the worker node's `IMDS` credentials, each pod needs its own least-privilege, cryptographically verifiable identity for cloud APIs (`S3`, `KMS`, `GCS`, `Azure Key Vault`). Kubernetes replaced static `etcd` secrets with Bound ServiceAccount Token Volumes (`KEP-1205`, GA in Kubernetes `1.22` [464]), disabled automatic `Secret` token generation (`KEP-2799`, default since Kubernetes `1.24` [467]), exposed OpenID Connect Discovery metadata at `/.well-known/openid-configuration` (`KEP-1393` [474]), and embedded immutable worker-node UIDs and per-token audit identifiers (`KEP-4193`, GA in Kubernetes `1.32` [468]).

When `kubelet` starts a pod on a Linux node, it mounts a memory-backed `projected` volume (`tmpfs`, never written to underlying block storage) and calls the `TokenRequest` subresource (`POST /api/v1/namespaces/<ns>/serviceaccounts/<sa>/token`) on `kube-apiserver` [464]. The API server signs a compact `RS256` or `ES256` JWT whose payload binds four orthogonal dimensions simultaneously:

```json
{
  "aud": ["sts.amazonaws.com"],
  "exp": 1763242685,
  "iat": 1763239085,
  "iss": "https://oidc.eks.us-west-2.amazonaws.com/id/0123456789ABCDEF",
  "jti": "9b2f8d1a-4c7e-4e92-8a11-71f0e8c3d402",
  "kubernetes.io": {
    "namespace": "payments",
    "node": {
      "name": "ip-10-42-18-9.us-west-2.compute.internal",
      "uid": "e4c81092-91ab-4d30-b922-0f8c1d7e2a19"
    },
    "pod": {
      "name": "ledger-api-6d8f9b7c4-xk2pq",
      "uid": "3a71f904-55b1-41e8-93d4-8b20c64e1190"
    },
    "serviceaccount": {
      "name": "ledger-sa",
      "uid": "c0192b44-12e0-4f88-a712-9901bc32a8f1"
    }
  },
  "nbf": 1763239085,
  "sub": "system:serviceaccount:payments:ledger-sa"
}
```

Examine what every field in this `KEP-1205` / `KEP-4193` payload prevents [464, 468]:
First, *Audience Isolation (`aud`)*: because `aud` is pinned explicitly to `["sts.amazonaws.com"]` (or `["api://AzureADTokenExchange"]`), if the AWS SDK or an intermediate proxy leaks this JWT, `kube-apiserver` itself rejects the token immediately because `kube-apiserver`'s own issuer audience is absent from `aud` [464].
Second, *Temporal and Lifecycle Binding (`exp` + `pod.uid`)*: `expirationSeconds` defaults to `3600` (1 hour, configurable down to `600` seconds), and `kubelet` proactively rotates the file atomically on `tmpfs` once 80% of its TTL has elapsed (`48` minutes) or within seconds of pod deletion; for internal `TokenReview` callers, `kube-apiserver` additionally verifies in real time that both `pod.uid` and `node.uid` still exist as live objects in `etcd`, revoking stolen tokens the instant a pod terminates [464, 468].
Third, *Node Provenance and Replay Correlation (`node.uid` + `jti`)*: introduced in `KEP-4193` [468], embedding `kubernetes.io.node.name` and `node.uid` lets downstream verifiers confirm that the pod token originated on the exact worker node presenting an mTLS node certificate, while `jti` (`RFC 7519` JWT ID) links every cloud STS exchange back to the exact `kube-apiserver` `TokenRequest` audit event.

Public clouds consume these projected JWTs through zero-secret federation protocols (`RFC 8693` OAuth 2.0 Token Exchange [475] and OpenID Connect Discovery [474]). Under AWS IAM Roles for Service Accounts (`IRSA` [473]), a mutating admission webhook injects `AWS_WEB_IDENTITY_TOKEN_FILE` and `AWS_ROLE_ARN` into the pod; the AWS SDK calls `sts:AssumeRoleWithWebIdentity`, AWS IAM verifies the signature and `exp` against the cluster's public JWKS keys (`KEP-1393` [474]), and evaluates an IAM Trust Policy condition requiring exact string equality on `aud` and `sub` (`"system:serviceaccount:payments:ledger-sa"`). To remove per-cluster IAM OIDC provider limits and attach dynamic session tags (`eks-cluster-name`, `kubernetes-namespace`, `kubernetes-pod-name`), AWS introduced `EKS Pod Identity` [476]: pods present their projected `TokenRequest` JWT to a node-local `eks-pod-identity-agent` DaemonSet on link-local `169.254.170.23`, which calls `AssumeRoleForPodIdentity` over the node's own channel while keeping `169.254.169.254` unreachable to pods! Google Cloud's `Workload Identity Federation for GKE` (`gke-metadata-server` intercepting `169.254.169.254` per pod [471]) and Microsoft Azure's `Entra Workload ID` (exchanging `api://AzureADTokenExchange` JWTs [472]) enforce the identical zero-static-secret invariant.

### `CNCF SPIFFE` and `SPIRE`: Hardware-to-Kernel Attestation and Bundle Federation

Cloud OIDC federation solves pod-to-cloud-API authentication, yet production systems also run thousands of east-west RPC flows across heterogeneous Linux substrates: Kubernetes microservices calling bare-metal `PostgreSQL` nodes, `systemd` daemons on on-premises Linux appliances streaming events to cloud Kafka brokers, and multi-cloud service meshes spanning AWS, GCP, and colocation cages. Managing internal X.509 PKI private keys on disk or relying on CNI IP-address allowlists (which fracture across NAT gateways, BGP load balancers, and pod IP recycling) reintroduces static secrets and network-location trust.

Graduated by the Cloud Native Computing Foundation, `SPIFFE` (*Secure Production Identity Framework for Everyone* [469]) standardizes workload identity across five composable specifications:
First, the `SPIFFE ID` specification (`SPIFFE-ID.md` [469]) assigns every workload an `RFC 3986` URI of the form `spiffe://<trust-domain>/<path>` (for example, `spiffe://prod.acme.internal/ns/payments/sa/ledger-api`), mandating a lowercase authority without ports, userinfo, percent-encoding, query strings, fragments, or relative path segments (`.` or `..`) up to `2048` bytes.
Second, the `X.509-SVID` specification (`X509-SVID.md` [477]) encodes that URI inside a short-lived X.509v3 leaf certificate (`basicConstraints: cA=FALSE`, critical `keyUsage: digitalSignature`), enforcing a crucial structural rule: *an `X.509-SVID` MUST contain at most one `URI` Subject Alternative Name (`SAN`), and verifiers MUST reject any certificate carrying two or more `URI` SANs* [477], eliminating principal-ambiguity bugs across TLS and `RFC 8705` mutual-TLS proxies [478]!
Third, for Layer 7 HTTP/gRPC intermediaries where end-to-end TLS is terminated by an L7 load balancer, the `JWT-SVID` specification (`JWT-SVID.md` [479]) defines a compact JWS bearer token restricting `alg` strictly to asymmetric `RS256/384/512`, `ES256/384/512`, or `PS256/384/512` (banning `alg: none` and symmetric `HS256` key-confusion attacks outright!) and requiring explicit `sub` (`SPIFFE ID`), narrow `aud`, and tight `exp` claims.

![Figure: Zero-secret workload identity bootstrapping in CNCF SPIRE: combining hardware/cloud Node Attestation (TPM 2.0 DevID/Quote or Cloud IID) with Linux kernel Workload Attestation (SO_PEERCRED, pidfd, binary SHA-256, and cgroup v2 pod selectors) to stream short-lived X.509-SVIDs in RAM.](diagrams/16-spiffe-spire-attestation.svg)

How does `SPIRE` (*the SPIFFE Runtime Environment* [470]) mint those `X.509-SVID` and `JWT-SVID` credentials to a freshly spawned Linux process without storing a single bootstrap token on disk? By chaining *Node Attestation* into *Linux Kernel Workload Attestation* [470, 480]:

![Figure: SPIFFE/SPIRE two-tier attestation and cross-domain federation: anchoring host Agent SVIDs in TPM 2.0 IEEE 802.1AR IDevID or Cloud IIDs, verifying local peers via Ring 0 SO_PEERPIDFD and cgroup v2 selectors, and federating Trust Bundles across clusters via https_spiffe.](diagrams/16-extra-spire-node-and-workload-attestation.svg)

Stage 1 is *Node Attestation* (`spire-agent` $\leftrightarrow$ `spire-server`) [470]. When a bare-metal Linux server or cloud VM boots, `spire-agent` starts with zero credentials and proves physical or hypervisor provenance to `spire-server`. On bare-metal Linux hosts equipped with a discrete or firmware `TPM 2.0`, `SPIRE`'s `tpm_devid` node attester leverages an `IEEE 802.1AR` factory-installed or enterprise-enrolled Device Identity (`IDevID` / `LDevID`) keypair and X.509 certificate stored inside non-exportable TPM NV indices [470, 481]: `spire-agent` generates an ephemeral Attestation Key (`AK`) inside the TPM, uses `TPM2_Certify` signed by the `DevID` key to prove both keys reside in the same hardware TPM, and completes a `TPM2_ActivateCredential` challenge-response with `spire-server` (often paired with `Keylime` runtime `IMA`/`PCR` verification from [Chapter 4](04-ima-ipe-keylime.md) [53]). On public clouds, `spire-agent` presents the hypervisor-signed instance document (`aws_iid` RSA/PKCS#7 EC2 Instance Identity Document, `gcp_iit` signed JWT, or `azure_msi`) or a node-bound Kubernetes `TokenRequest` token (`k8s_psat`, verified by `spire-server` via `TokenReview` checking `kubernetes.io.node.uid` [468, 470]). Crucially, `spire-server` enforces *Trust-On-First-Attest (`TOFA`)* for one-shot IID documents so a stolen IID cannot re-attest the node from outside, mints a short-lived node `Agent SVID` (`spiffe://prod.acme.internal/spire/agent/tpm_devid/...`), and streams down *only* the workload registration entries whose parent selector matches that exact attested node [470]! Even if an attacker achieves root compromise on Worker Node A, `spire-agent` on Node A cannot request an `SVID` for `vault-unsealer` if `vault-unsealer` is scheduled exclusively on Node B.

Stage 2 is *Kernel Workload Attestation* (`workload` $\leftrightarrow$ `/run/spire/sockets/agent.sock`) [69, 470, 480]. Per Section 4.1 of the `SPIFFE Workload API` specification (`SPIFFE_Workload_API.md` [480]), workloads present *zero* client authentication secret when calling `FetchX509SVID` or `FetchJWTSVID` over the read-only UNIX domain socket `/run/spire/sockets/agent.sock`. Instead, upon `accept()`, `spire-agent` queries the Linux kernel directly via `getsockopt(conn_fd, SOL_SOCKET, SO_PEERCRED, &ucred, &len)` and `SO_PEERPIDFD` ([Chapter 11](11-systemd-dbus-sandboxing.md) [69]), obtaining an unforgeable kernel process descriptor (`pidfd`) immune to numeric PID wrap-around races [69, 470]. `SPIRE`'s `unix`, `systemd`, and `k8s` workload attester plugins then interrogate Ring 0 and local control-plane state against that exact `pidfd`: the `unix` attester resolves `uid`, `gid`, and computes the `SHA-256` digest of `/proc/<pid>/exe` (`unix:sha256:...`, immutable at runtime when `/usr` is backed by `dm-verity` or `fs-verity` from [Chapter 3](03-luks2-verity.md)); the `systemd` attester queries `PID 1` for the caller's exact unit (`systemd:id:postgres.service`); and the `k8s` attester parses `/proc/<pid>/cgroup` (`cgroups v2` unified hierarchy) to extract the container ID and `Pod UID`, cross-verifying the live pod specification, `ServiceAccount`, namespace, and container image `SHA-256` digest against the node-local `kubelet` API [470]. When every selector matches, `spire-agent` generates a fresh `ECDSA P-256` private key in memory, obtains a 1-hour `X.509-SVID` from `spire-server`, and streams the leaf SVID, private key, and `Trust Bundle` over gRPC to `Envoy`, `Cilium`, or `go-spiffe`, rotating keys silently at half-life with randomized splay without touching disk or restarting processes [477, 480].

Finally, how do microservices in `spiffe://prod-aws.corp` authenticate peers in `spiffe://onprem-pci.corp` or a partner organization without sharing a root CA private key? Through `SPIFFE Federation` (`SPIFFE_Federation.md` [482]): each `SPIRE Server` exposes an HTTPS *Bundle Endpoint* serving an `RFC 7517` JWK Set containing its X.509 root CAs (`use: "x509-svid"`) and JWT public keys (`use: "jwt-svid"`, `kid` required) [477, 479, 482]. Peer `SPIRE` servers poll federated endpoints via `https_spiffe` (authenticated by the remote server's `X.509-SVID`) or `https_web` (Web PKI TLS), streaming updated `federated_bundles` and instant CA revocations down to local workloads automatically [480, 482].

## Distro, Immutable-OS, & Cloud Trade-Offs

Selecting and hardening a Linux workload identity plane involves concrete architectural trade-offs across public-cloud managed Kubernetes, immutable container OS distributions (`Talos Linux`, `Bottlerocket`, `Flatcar` [45]), and hybrid bare-metal infrastructure:

| Mechanism | Primary Substrate | Credential Artifact & Lifetime | Replay Resistance | Key Operational Constraint |
|---|---|---|---|---|
| `IMDSv2` (`HttpTokens=required`, `HopLimit=1`) | Single-purpose EC2 / Cloud VMs | STS Temporary Role Keys (`1h` to `6h` TTL) | Bearer token; `TTL=1` blocks routed pods at L3 [81] | Instance-wide blast radius; never expose to multi-pod K8s nodes [81, 462] |
| K8s Bound `TokenRequest` + Cloud OIDC (`IRSA` / `GKE` / `AKS`) | Cloud Managed Kubernetes (`EKS`, `GKE`, `AKS`) | Projected OIDC `JWT` (`10m` to `1h` TTL) exchanged for Cloud STS token [464, 473] | Bearer `JWT` scoped by `aud`, `sub`, `pod.uid`, and `node.uid` [464, 468] | Requires public/reachable JWKS endpoint or `EKS Pod Identity` agent (`169.254.170.23`) [474, 476] |
| `CNCF SPIFFE` `JWT-SVID` | Layer-7 HTTP / API Gateways | Compact `JWS` (`ES256`/`RS256`, typically `5m` TTL) [479] | Bearer token; vulnerable to theft at L7 termination if `aud` is wide [479] | Keep `aud` single-service and `exp <= 300s`; prefer `X.509-SVID` wherever mTLS passes through [479] |
| `CNCF SPIFFE` `X.509-SVID` via `SPIRE` (`tpm_devid` + `SO_PEERPIDFD`) | Hybrid K8s, Bare-Metal Linux, Multi-Cloud Service Meshes | `ECDSA P-256` X.509v3 leaf cert (`1h` TTL, single `URI` SAN) in RAM [477] | Proof-of-possession mTLS (`RFC 8705`); stolen cert useless without RAM private key [477, 478] | Must operate HA `spire-server` + protect `/run/spire/sockets/agent.sock` with `SELinux` MCS & no `hostPID` [470] |

On immutable Linux worker distributions such as `Talos Linux` (which eliminates SSH and shell access entirely, managing node configuration via mTLS gRPC APIs [45]) and AWS `Bottlerocket` (which ships with `SELinux` `Enforcing`, `dm-verity` rootfs, and `IMDSv2` `HopLimit = 1` defaults [45, 81]), mounting `SPIRE`'s CSI driver (`spiffe.csi.driver`) injects `/run/spire/sockets/agent.sock` into pods without brittle `hostPath` volumes [470]. Regardless of distribution, two host-isolation rules govern `SPIRE` worker nodes: untrusted pods must never run with `hostPID: true`, because sharing the host PID namespace without `Yama` (`kernel.yama.ptrace_scope >= 1`), dropped `CAP_SYS_PTRACE`, and distinct `SELinux` Multi-Category Security (`MCS`) categories (`s0:c1,c2`) would allow a compromised sibling process under the same numeric UID to `ptrace(PTRACE_ATTACH)` or read `/proc/<sibling>/mem` to extract an in-RAM `X.509-SVID` private key; and registration selectors should pin immutable properties (`k8s:sa` plus `k8s:pod-image:sha256:...` or `unix:sha256:...` over `dm-verity`) rather than mutable pod labels [470].

## Seam Failures, CVEs, & Structural Bounds

Real-world workload identity breaches consistently target residual `IMDSv1` fallbacks, `HopLimit >= 2` IaC misconfigurations, unbound or path-traversed Kubernetes tokens, and normalization or race defects at node and UNIX-socket attestation boundaries.

| Incident / CVE | Year | Subsystem | Broken Assumption | Exploit Mechanism | Architectural Fix |
|---|---|---|---|---|---|
| Capital One WAF `IMDSv1` Breach | 2019 | AWS `IMDSv1` (`169.254.169.254`) + Apache WAF | Link-local metadata is unreachable from external HTTP clients | Misconfigured reverse proxy relayed `GET` SSRF to `/iam/security-credentials/ISSRole-WAF`, leaking S3 STS keys | Enforce `IMDSv2` (`HttpTokens=required` rejecting `GET` and `X-Forwarded-For`) [81, 462, 466] |
| Container `IMDSv2` Bypass via `HopLimit >= 2` | 2020-2025 | Cloud IaC (`Terraform` / `CloudFormation` node templates) | Raising `HttpPutResponseHopLimit = 2` safely fixes legacy SDKs in pods | `IP TTL = 2` survives `veth` forwarding (`2 - 1 = 1`), letting any RCE pod run `curl -X PUT` to steal node IAM role | Enforce `HopLimit = 1`, block `hostNetwork`, drop pod egress to `169.254.0.0/16`, and use OIDC / Pod Identity [81, 465, 473, 476] |
| Legacy Non-Bound K8s `Secret` SA Token Replay | 2018-2023 | Static `kubernetes.io/service-account-token` Secrets | Stolen pod SA token expires with pod and works only on target service | Non-expiring `etcd` JWT lacked `aud`, `exp`, and `pod.uid`, granting permanent off-cluster `kube-apiserver` access | Mandate `KEP-1205`/`4193` `TokenRequest` projected volumes and `KEP-2799` no-auto-secret default [464, 467, 468] |
| `CVE-2021-25745` (`ingress-nginx` SA Token Theft) | 2022 | Kubernetes `ingress-nginx` controller | Ingress `spec.rules.http.paths.path` cannot reference local pod files | Crafted `nginx` `alias` directive pointed at `/var/run/secrets/kubernetes.io/serviceaccount/token`, leaking cluster-wide Ingress SA JWT | Sanitize Ingress path/annotations, run `chroot` `nginx`, and scope controller RBAC [483] |
| `CVE-2024-3177` (`enforce-mountable-secrets` Bypass) | 2024 | `kube-apiserver` `ServiceAccount` admission plugin | Annotation `enforce-mountable-secrets` blocks all unlisted `Secret` reads | Admission checked `volumes` mounts while overlooking `envFrom.secretRef` on containers and ephemeral containers | Patch `ServiceAccount` admission controller to validate `envFrom` across all container types [484] |
| `CVE-2021-27098` (`SPIRE` Legacy Node API Impersonation) | 2021 | `SPIRE Server` Node API (`< 0.12.1`) | Attested `spire-agent` can request SVIDs only for workloads mapped to its own node | Missing caller-node authorization check in legacy RPC allowed one compromised agent to mint SVIDs for other nodes | Remove legacy Node API and enforce strict per-agent node-to-entry graph authorization in `SPIRE` [485] |
| `CVE-2021-27099` (`SPIRE` `aws_iid` Path Traversal) | 2021 | `SPIRE` `aws_iid` Node Attestor (`< 0.12.1`) | Constructed `SPIFFE ID` path from EC2 IID fields cannot escape agent namespace | Unsanitized path segments in `agent_path_template` permitted `..` traversal into arbitrary `SPIFFE ID` paths | Canonicalize and validate strict `SPIFFE ID` segment character rules before minting Agent SVIDs [469, 485] |
| Custom `SO_PEERCRED` PID-Recycle Attester Race | 2020-2023 | Custom UNIX-socket workload attesters | Numeric `ucred.pid` still belongs to the connecting process when `/proc/<pid>/cgroup` is read | Short-lived child connects to socket and `exit()`s immediately so privileged process reuses PID during `/proc` lookup | Use `SO_PEERPIDFD` (`pidfd`) + `starttime` revalidation (`SPIRE` `unix` attester) and isolated PID namespaces [69, 470] |

Pause over a profound structural bound at the edge of workload identity: `IMDSv2`, `KEP-1205` projected JWTs, and `SPIFFE` `X.509-SVID`s prove *which verified binary and pod* is making an outbound call, assuming that binary's internal logic faithfully represents operator intent. What happens when the workload *itself* is an autonomous AI coding agent, an LLM code interpreter, or a `Model Context Protocol` (`MCP`) server whose next shell command is steered dynamically by untrusted text inside a pull request or Slack message? If that agent holds *any* bearer token inside its address space, an Indirect Prompt Injection simply instructs the agent to read `$GITHUB_TOKEN` and transmit it outward! Confining untrusted agentic execution and moving real credentials *completely outside* the Linux sandbox into a host-side reverse proxy is the mission of [Chapter 17](17-ai-agent-sandboxes.md).

## Inspecting on a Live Linux Host

Probe whether the current Linux cloud host still permits unauthenticated `IMDSv1` `GET` queries (`HTTP 200` indicates exposed `IMDSv1`; `HTTP 401` confirms `IMDSv2` `HttpTokens=required` is active; timeout confirms link-local blocking or non-cloud hardware):

```bash
curl -s -o /dev/null -w "IMDSv1 GET status: %{http_code}\n" --connect-timeout 1 http://169.254.169.254/latest/meta-data/ 2>/dev/null || echo "169.254.169.254 blocked or non-cloud host"
```

Verify `IMDSv2` stateful `PUT` token acquisition and inspect the IPv4 `TTL` hop-limit stamped on the hypervisor response (`ttl=1` proves routed containers are blocked at Layer 3):

```bash
# Requires a cloud VM with IMDSv2 reachable from the current network namespace
TOK=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" --connect-timeout 1 2>/dev/null || true)
[ -n "$TOK" ] && echo "IMDSv2 session token acquired (${#TOK} bytes)" || echo "No IMDSv2 token returned in this netns"
```

Decode the unencrypted JSON payload of a projected Kubernetes `KEP-1205` / `KEP-4193` ServiceAccount JWT (checking `aud`, `exp`, `pod.uid`, and `node.uid` without printing the raw signature) and check for an active `SPIRE` Workload API UNIX socket:

```bash
ls -la /var/run/secrets/kubernetes.io/serviceaccount/token /run/spire/sockets/agent.sock 2>/dev/null || true
[ -r /var/run/secrets/kubernetes.io/serviceaccount/token ] && cut -d. -f2 /var/run/secrets/kubernetes.io/serviceaccount/token | base64 -d 2>/dev/null | tr ',' '\n' | head -n 14 || true
```

Audit host `nftables` or `iptables` `FORWARD` chains confirming container pod subnets cannot route packets to `169.254.169.254` or `169.254.0.0/16`:

```bash
# Inspecting netfilter tables requires CAP_NET_ADMIN (root / run0)
nft list ruleset 2>/dev/null | grep -C 2 "169.254" || iptables -S FORWARD 2>/dev/null | grep "169.254" || true
```

