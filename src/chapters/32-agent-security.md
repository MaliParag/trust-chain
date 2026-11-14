# Workload and AI Agent Security

## Overview

* **Role in the Chain:** Extends host sandboxing ([Windows Access Control](25-access-control.md), Chapter 10; [Code Integrity](06-code-integrity.md), Chapter 7) and cloud session enforcement ([Zero Trust](13-zero-trust.md), Chapter 19; [Continuous Access Evaluation](14-cae.md), Chapter 20) to non-human workloads and autonomous or semi-autonomous AI agents spanning the Windows 11 endpoint and `Microsoft Entra ID`.
* **Core Security Invariant:** Non-human workloads and AI agents execute under distinct, auditable identities (`Local Agent SIDs` on Windows and `Entra Agent Identities` in the cloud) whose effective authority is bounded to the intersection of human delegator and agent blueprint scopes, isolated from the user's ambient session credentials and blocked from Tier-0 administrative roles.
* **Trusted Computing Base (TCB):** The Windows 11 `Agent Workspace` session manager, `ntoskrnl.exe` `AppContainer` / `LPAC` token reference monitor, the Windows `Model Context Protocol` (`MCP`) Registry and Proxy Broker, `Microsoft Entra ID` STS and `Entra Agent ID` Blueprint control plane, and deterministic resource-server egress and `Conditional Access` policy enforcement points.
* **Primary Failure Modes:** Zero-click indirect prompt injection (`XPIA`) turning RAG/mail agents into confused deputies (`EchoLeak`, `CVE-2025-32711`), running desktop or coding agents inside the user's primary interactive session with ambient `DPAPI`/browser/filesystem access, `MCP` tool-description poisoning and unsigned server command injection, and over-privileged or orphaned OAuth `Service Principals` (`Midnight Blizzard`, 2024).
* **Handoff:** Governs identity, delegation, and containment for software workloads and AI agents, handing off hardware-attested encrypted memory isolation against untrusted cloud host operators to [Confidential VMs](29-confidential-vms.md) (Chapter 22).

## Core Engineering Problem & Threat Model

Every link examined in Chapters 1 through 20 rested on a silent thirty-year assumption of operating-system and identity design: *the software holding a user's access token is a deterministic program faithfully executing the user's intent.* When `explorer.exe` opens a document or Outlook presents a `CAE`-capable `Bearer` token, the application's control flow is fixed by compiled machine instructions verified by `ci.dll` / `skci.dll` ([Chapter 7](06-code-integrity.md)).

Modern enterprise environments break that assumption along two distinct axes:

1. **Scale of Deterministic Non-Human Workloads:** In cloud tenants, non-human identities (`App Registrations`, `Service Principals`, `Managed Identities`, and CI/CD `OIDC` federated workloads) routinely outnumber human employees by an order of magnitude [903]. These workloads never type a `Windows Hello` PIN, cannot complete interactive MFA challenges, and historically accumulated long-lived client secrets and tenant-wide `Application` permissions (such as Exchange `full_access_as_app` or Graph `RoleManagement.ReadWrite.Directory`) with no human owner accountable when a project ended [840, 903].
2. **Nondeterministic AI Agents and Instruction-Data Collapse:** AI agents powered by large language models (`LLMs`) read untrusted external content (inbound emails, web pages, shared documents, pull requests, and tool responses) and dynamically invoke tools (`filesystem`, `shell`, `browser`, `Model Context Protocol` servers, and `Microsoft Graph` APIs) [905, 906]. Because an `LLM` processes system instructions, user goals, and untrusted external data inside a single token context window without a hardware-enforced Von Neumann instruction/data boundary, *indirect prompt injection* (`XPIA`) embedded inside untrusted data can steer the model's next tool invocation [905].

Viewed through Norman Hardy's 1988 *Confused Deputy* formulation [363], running an AI agent inside the user's primary Windows desktop session or issuing it a full-scope user OAuth token is architecturally fatal. If user $u$ possesses ambient authority $\mathcal{A}(u)$ over local `DPAPI` vaults, SSH keys, corporate mail, and internal SharePoint sites, and an agent $a$ inherits $\mathcal{A}(u)$ directly while reading untrusted external input $d$, any adversarial payload inside $d$ exercises $\mathcal{A}(u)$ without exploiting a single memory-corruption bug or forging a single cryptographic signature [905, 909]. Securing workloads and agents therefore requires splitting agent identity and execution out of the human's ambient authority domain on both the Windows endpoint and the cloud identity provider.

## Architectural Deep Dive

### On-Box Containment: Windows 11 Agent Workspace, Local Agent SIDs, and LPAC

When desktop-automation or local coding agents execute inside the user's interactive logon session (`Session 1`, running under the user's `Medium-IL` token), they inherit automatic read/write access to `%USERPROFILE%`, `%APPDATA%`, unlocked `DPAPI` `MasterKeys` ([Chapter 11](30-data-protection.md)), active browser profiles, and local named pipes. To eliminate ambient session sharing, Windows 11's agentic OS architecture enforces four host-level isolation boundaries [901, 906, 907]:

![Windows 11 agentic containment: interactive user session versus isolated Agent Workspace and signed MCP proxy](diagrams/32-windows-agent-workspace-mcp.svg)

1. **Distinct Local Agent Accounts (`Agent SIDs`):** Rather than impersonating the human user's `SID`, Windows provisions a dedicated, non-interactive local agent account with its own security identifier (`SID`) [901, 907]. Kernel `SeAccessCheck` ([Chapter 10](25-access-control.md)) and `ETW` / Security Event Log telemetry (`4688` process creation, `4663` object access) attribute every file write, network socket, and child process unambiguously to the agent principal rather than blending agent actions into human user telemetry [901].
2. **Isolated `Agent Workspace` Session:** Agents that interact with GUI or Win32 applications execute inside a separate, policy-controlled `Agent Workspace` desktop session isolated from the human's primary interactive desktop [901, 907]. Within the workspace, the agent cannot scrape windows (`UIPI` / desktop boundary), inject keystrokes into the user's elevated terminals, or call `CryptUnprotectData` against the human user's `DPAPI` secrets. Filesystem visibility is deny-by-default outside explicitly delegated Known Folders (such as user-approved `Documents` or project workspaces) [907].
3. **`AppContainer` and Less Privileged AppContainer (`LPAC`) Tool Sandboxes:** Individual tool runners and connectors execute inside `AppContainer` (`S-1-15-2-*`) or `LPAC` tokens [381, 906]. Unlike standard restricted tokens, an `LPAC` token strips the implicit `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) SID, denying read access even to general OS/application directories unless an explicit `Capability SID` (`internetClient`, `documentsLibrary`, or custom named capability) matches the target object's `DACL` [381].
4. **Signed `Model Context Protocol` (`MCP`) Registry and Proxy Broker:** `MCP` standardizes how agent hosts (`VS Code`, Copilot, custom orchestrators) invoke local or remote tools over `JSON-RPC` [906]. Unmediated `MCP` servers spawned as raw `stdio` child processes create severe supply-chain, command-injection, and silent tool-mutation risks. Windows 11 interposes an OS `MCP` Proxy Broker backed by a vetted Windows `MCP` Registry: local `MCP` servers must carry valid publisher code signatures ([Chapter 7](06-code-integrity.md)) enabling central revocation via `App Control` (`WDAC`), declare static tool schemas up front, and pass through OS-rendered user consent and policy enforcement before invoking sensitive host capabilities [906].

### Cloud Workload Identities vs. Microsoft Entra Agent ID

In the cloud plane, Microsoft separates deterministic machine workloads from autonomous and semi-autonomous AI agents across distinct directory object classes [903, 908]:

* **Deterministic Workloads (`Managed Identities` and `OIDC` Federation):** For static Azure microservices, VM scale sets, and GitHub Actions pipelines whose API targets are fixed in code, `Managed Identities for Azure Resources` and `Workload Identity Federation` eliminate exportable client secrets entirely: Azure's fabric (`IMDS` on `169.254.169.254` or platform OIDC issuer) mints short-lived tokens bound to the compute resource, evaluated under Conditional Access for Workload Identities (restricting IP ranges and blocking sign-in on Entra risk detection) [903].
* **Why Classic `Service Principals` Fail for AI Agents:** A classic `Service Principal` was designed for predictable service-to-service code. Using `Service Principals` for AI agents creates three structural gaps: static tenant-wide app roles bypass per-user delegation context, unmanaged sprawl leaves millions of ownerless apps active after creators change teams, and compromised app credentials can hold Tier-0 directory roles [908]. Conversely, assigning a standard human `Entra User` account to an AI agent pollutes human audit logs and breaks interactive `MFA`/`WHfB` enforcement [908].

To close both gaps, `Microsoft Entra Agent ID` introduces a dedicated three-object governance hierarchy purpose-built for agentic workloads [908]:

![Microsoft Entra Agent ID three-object governance, OBO intersection, and Conditional Access plane](diagrams/32-entra-agent-id-blueprint.svg)

1. **`Agent Identity Blueprint`:** The parent definition template recording the agent class, publisher verification, maximum inheritable permission ceiling, credential rotation policy (managed via the Entra Auth SDK sidecar without hardcoded secrets), and lifecycle rules [908].
2. **`Agent Identity` (Persistent or Ephemeral):** Runtime instances instantiated from a `Blueprint`. Every `Agent Identity` enforces three platform invariants unavailable on generic service principals [908]:
   * **Mandatory Human Sponsorship:** Every agent requires an accountable human sponsor at creation; built-in Entra Governance lifecycle workflows automatically transfer or suspend orphaned agents when a sponsor changes roles or leaves the organization [908].
   * **Platform Blast-Radius Ceiling:** Entra blocks `Agent Identities` at the platform layer from being assigned privileged Tier-0 directory roles (such as `Global Administrator` or `Privileged Role Administrator`).
   * **Ephemeral Lifecycle:** Orchestrators can spin up task-scoped `Agent Identities` dynamically from a `Blueprint` and cascade-delete them upon task completion [908].
3. **Paired 1:1 `Agent User` (Only When Required):** For collaboration APIs that structurally require a directory user object (such as an `Exchange` mailbox or `Teams` participant), Entra pairs a restricted 1:1 `Agent User` object to its parent `Agent Identity` with explicit machine-identity telemetry markers [908].

### Cryptographic Delegation (`OBO` vs. `Autonomous`) and Policy Enforcement

When an agent acts On-Behalf-Of (`OBO`) a human user $u$ (interactive or delegated mode), issuing the agent an indistinguishable user token violates least privilege. Under `OAuth 2.0 Token Exchange` (`RFC 8693`) and `Entra Agent ID` delegation semantics, the token carries distinct subject (`sub`), authorized party / agent identity (`azp` / `act` actor claim), and narrow resource audience (`aud`) claims [904, 908]. A compliant Policy Enforcement Point (`PEP`) grants access to resource $r$ only under *conjunctive intersection*:

$$\mathrm{Grant}_{\text{OBO}}(u, a, r) \iff \mathrm{Perm}(u, r) \land \mathrm{Scope}(a, r) \land \mathrm{ConditionalAccess}(u, a, \text{risk})$$

An email-summarizer agent invoked by a Chief Financial Officer therefore cannot modify payroll records even though the CFO holds payroll permissions, because `Scope(a, payroll) = false`; conversely, the same agent invoked by an intern cannot read executive board decks even if the agent blueprint supports SharePoint retrieval, because `Perm(intern, board_deck) = false`. When an agent operates in Autonomous (`Non-OBO`) mode without a live human session, dedicated Conditional Access for Agents templates evaluate agent identity risk, blueprint attestation, network boundaries, and `Continuous Access Evaluation` (`CAE`) revocation watermarks [908].

## Attack Catalog & Gap Analysis

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `Midnight Blizzard` Legacy OAuth Pivot | 2024 | Test tenant OAuth app -> Corporate Exchange mail | Compromised legacy test tenant credential | Abused legacy test OAuth app to provision malicious service principals granted `full_access_as_app` on Exchange Online [840, 841] | Decommission unused apps (`1.4M` retired under SFI), enforce Workload CA, and gate app role grants [912] |
| Illicit OAuth Consent Phishing | 2020-present | User MFA / passkey bypass via delegated OAuth grant | Victim tricked into clicking `/authorize` consent link | Tricks user into granting attacker multi-tenant app `Mail.Read` / `Files.ReadWrite.All` refresh tokens without stealing password [903] | Restrict user consent to verified publishers + admin consent workflows in Entra ID |
| `EchoLeak` (`CVE-2025-32711`) | 2025 | Zero-click external email -> M365 Copilot tenant exfiltration | Ability to send external email to target mailbox | Indirect prompt injection (`XPIA`) evades classifier during RAG indexing, pulls internal M365 context, and auto-exfiltrates via allowed URL/image rendering [909] | Enforce strict egress/CSP origin locks, scope isolation between external/internal RAG tiers, and deterministic output filters [909] |
| Ambient-Session Desktop Agent `XPIA` | 2024-2026 | Untrusted web/doc content -> User `DPAPI` & local files | Agent running in user's primary Windows session | Hidden DOM/document instructions steer computer-use or coding agent to read `~/.ssh`, `.env`, or cookies and POST outward [905, 907] | Run agents strictly inside Windows 11 `Agent Workspace` under a separate local Agent `SID` + `LPAC` [907] |
| `MCP` Tool Poisoning & Rug-Pulls | 2025-2026 | Trusted MCP host -> Arbitrary local RCE / secret leak | Unsigned or mutable third-party `MCP` server | Embeds hidden prompt instructions inside MCP tool JSON `description` metadata or mutates tool behavior post-consent [906] | Enforce signed servers via Windows `MCP` Registry/Proxy, `WDAC` publisher pinning, and schema hash locking [906] |
| Orphaned Workload Secrets & Over-Scoped `SPNs` | 2019-present | Stale CI/CD secret -> Persistent cloud lateral movement | Leaked client secret in repo/build log | Replays long-lived `client_secret` of ownerless `Service Principal` bypassing human MFA and password rotation [903, 908] | Replace secrets with `Managed Identities` / `OIDC` federation and migrate agents to `Entra Agent ID` with enforced sponsors [908] |

### Gap Analysis: EchoLeak (`CVE-2025-32711`) and the Confused-Deputy Anatomy

Disclosed by Aim Labs in June 2025, `EchoLeak` (`CVE-2025-32711`) demonstrated the first zero-click indirect prompt injection exfiltration chain against an enterprise production AI system (`Microsoft 365 Copilot`) [909]:

![Indirect prompt injection as a confused-deputy chain in EchoLeak CVE-2025-32711](diagrams/32-agent-confused-deputy-xpia.svg)

1. **Cross-Boundary Ingestion:** An external unauthenticated attacker sent a benign-looking email to an employee containing concealed adversarial instructions phrased without standard jailbreak keywords to bypass inbound `XPIA` classifiers [909].
2. **RAG Scope Collapse:** Later, when the employee asked Copilot a routine workplace question, Copilot's Retrieval-Augmented Generation (`RAG`) pipeline retrieved both the untrusted external email and confidential internal SharePoint/OneDrive files into the same LLM context window under the user's `OBO` Graph permissions [909].
3. **Zero-Click Side-Channel Exfiltration:** Although outbound Content Security Policy (`CSP`) blocked arbitrary external `<img>` domains, the injected prompt instructed the model to format sensitive internal data as query parameters inside an auto-fetched or trusted-domain proxy URL (`SharePoint` / `Teams` link-preview / reference-style Markdown), exfiltrating internal secrets to the attacker's server without the user clicking a link [909].

`EchoLeak` illustrates why prompt-level classifiers (`XPIA` filters) are necessary defense-in-depth yet *cannot serve as a security boundary*: the vulnerability lay not in how well the model spotted clever wording, but in combining *untrusted external input*, *high-privilege internal data access*, and *an open outbound communication channel* inside a single execution context [905, 909].

> **Key idea.**
> Because an LLM processes instructions and untrusted data in one shared representation without a formal grammar boundary, natural-language prompt filtering cannot guarantee isolation. Sound agentic architecture assumes the model itself can be subverted by untrusted context and enforces hard security boundaries outside the model: distinct OS `Agent SIDs` and `LPAC` sandboxes on the host, `OBO` permission intersection (`Perm(User) AND Scope(Agent)`) in the token, and deterministic egress allowlists on the network.

## Theoretical Limits & Structural Invariants

* **Undecidability of Prompt-Injection Detection Over Natural Language:** Because an `LLM` maps arbitrary token sequences continuously into latent representations without a formal grammar separating code from data, deciding whether an arbitrary natural-language or multimodal input will steer model output toward an attacker goal is non-separable in general [905]. Security boundaries must therefore be enforced below and around the model (OS process/account isolation, `LPAC` DACLs, cryptographic `OBO` scope intersection, and deterministic network egress gates), never solely by system-prompt instructions.
* **Monotonicity of Delegation ($\mathcal{A}_{\text{effective}} \subseteq \mathcal{A}_{\text{caller}} \cap \mathcal{A}_{\text{agent}}$):** No agent invocation may amplify privileges beyond the invoking human's permissions (`privilege escalation`) or beyond the agent blueprint's declared task scope (`confused deputy`). Autonomous agents without an invoking human must carry explicit blueprint-capped roles disjoint from Tier-0 directory administration [908].
* **Accountability Requires Distinct Principal Attribution:** If an agent shares a human's `SID` locally or user `oid` in cloud logs, incident responders cannot distinguish human malice, compromised endpoints, and prompt-injected agent actions. Separate `Local Agent SIDs` and `Entra Agent IDs` preserve non-repudiation across `ETW` and Entra audit trails [901, 908].

## Inspecting and Verifying on a Running System

### Audit Local `AppContainer` / Sandbox Mappings and Agent Accounts on Windows

Enumerate local user accounts (verifying whether dedicated non-admin or agent workspace accounts exist and remain outside `Administrators`) and inspect active `AppContainer` firewall/sandbox profiles [381, 907]:

```powershell
Get-LocalUser | Select-Object Name, Enabled, SID, PrincipalSource
```

```powershell
Get-NetFirewallApplicationFilter | Where-Object AppContainerSid -ne "None" |
  Select-Object -First 10 Package, AppContainerSid
```

### Audit High-Privilege Cloud Workload `Service Principals` and Exportable Secrets

Using Microsoft Graph PowerShell, identify non-human `Service Principals` holding dangerous tenant-wide application roles (such as `full_access_as_app` or directory write roles) or carrying long-lived password credentials (`PasswordCredentials`) instead of `Managed Identities` / `Entra Agent ID` [903, 908]:

```powershell
Get-MgServicePrincipal -All -Property Id,DisplayName,ServicePrincipalType,PasswordCredentials |
  Where-Object { $_.PasswordCredentials.Count -gt 0 } | Select-Object DisplayName, ServicePrincipalType, Id
```

Inspect application role assignments granted to a specific workload or agent `ServicePrincipalId`:

```powershell
Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $SpObjectId |
  Select-Object PrincipalDisplayName, ResourceDisplayName, AppRoleId, CreatedDateTime
```

## Summary & Handoff

Non-human workloads and AI agents extend the Windows trust chain beyond interactive human sessions. On the Windows 11 host, `Agent Workspace`, distinct local `Agent SIDs`, `LPAC` capability tokens, and signed `MCP` proxy mediation strip agents of ambient access to the user's primary desktop and `DPAPI` vaults. In the cloud, `Managed Identities` eliminate static workload secrets while `Microsoft Entra Agent ID` binds AI agents to sponsor-governed blueprints, `OBO` permission intersections, Tier-0 role blocks, and `Conditional Access` / `CAE` enforcement.

Yet every cloud control examined in Chapters 19 through 21 still executes on physical datacenter servers operated by a cloud provider. The penultimate link asks how a workload or signing service protects its memory even from the cloud host hypervisor itself:

* **Excluding the Cloud Host Operator from Memory TCB:** Encrypting and integrity-protecting guest VM pages in silicon (`AMD SEV-SNP` and `Intel TDX`) and binding key release to hardware attestation belongs to [Confidential VMs](29-confidential-vms.md) (Chapter 22).
* **When a Cloud Signing Root Compromises Every Tenant Below It:** How a stolen root signing key and an omitted cross-tier issuer check bypassed the entire chain belongs to [When the Chain Snaps: Storm-0558](15-storm0558.md) (Chapter 23).
