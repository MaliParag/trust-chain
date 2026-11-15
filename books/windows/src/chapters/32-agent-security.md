# Workload and AI Agent Security

## Overview

* **Role in the Chain:** Extends host sandboxing ([Windows Access Control](25-access-control.md), Chapter 10; [Code Integrity](06-code-integrity.md), Chapter 7) and cloud session enforcement ([Zero Trust](13-zero-trust.md), Chapter 19; [Continuous Access Evaluation](14-cae.md), Chapter 20) to non-human workloads and autonomous or semi-autonomous AI agents spanning the Windows 11 endpoint and `Microsoft Entra ID`.
* **Core Security Invariant:** Non-human workloads and AI agents execute under distinct, auditable identities (`Local Agent SIDs` on Windows and `Entra Agent Identities` in the cloud) whose effective authority is bounded to the intersection of human delegator and agent blueprint scopes, isolated from the user's ambient session credentials and blocked from Tier-0 administrative roles.
* **Trusted Computing Base (TCB):** The Windows 11 `Agent Workspace` session manager, `ntoskrnl.exe` `AppContainer` / `LPAC` token reference monitor, the Windows `Model Context Protocol` (`MCP`) Registry and Proxy Broker, `Microsoft Entra ID` STS and `Entra Agent ID` Blueprint control plane, and deterministic resource-server egress and `Conditional Access` policy enforcement points.
* **Primary Failure Modes:** Zero-click indirect prompt injection (`XPIA`) turning RAG/mail agents into confused deputies (`EchoLeak`, `CVE-2025-32711`), running desktop or coding agents inside the user's primary interactive session with ambient `DPAPI`/browser/filesystem access, `MCP` tool-description poisoning and unsigned server command injection, and over-privileged or orphaned OAuth `Service Principals` (`Midnight Blizzard`, 2024).
* **Handoff:** Governs identity, delegation, and containment for software workloads and AI agents, handing off hardware-attested encrypted memory isolation against untrusted cloud host operators to [Confidential VMs](29-confidential-vms.md) (Chapter 22).

## Core Engineering Problem & Threat Model

Every link examined in Chapters 1 through 20 rested on a silent thirty-year assumption of operating-system and identity design: *the software holding a user's access token is a deterministic program faithfully executing the user's intent.* When `explorer.exe` opens a document or Outlook presents a `CAE`-capable `Bearer` token, the application's control flow is fixed by compiled machine instructions verified by `ci.dll` / `skci.dll` ([Chapter 7](06-code-integrity.md)).

Modern enterprise environments break that assumption along two distinct operational axes. First, deterministic non-human workloads have outgrown human directory populations: across enterprise cloud tenants, machine identities (`App Registrations`, `Service Principals`, `Managed Identities`, and CI/CD `OIDC` federated workloads) routinely outnumber human employees by an order of magnitude [903]. Unlike human staff, these workloads never enter a `Windows Hello` PIN or satisfy interactive MFA prompts, and over a decade of cloud adoption they accumulated long-lived client secrets alongside broad, tenant-wide `Application` permissions (such as Exchange `full_access_as_app` or Microsoft Graph `RoleManagement.ReadWrite.Directory`) with no accountable human sponsor remaining when projects ended [840, 903].

Second, autonomous and semi-autonomous AI agents powered by large language models (`LLMs`) collapse the classical boundary between program instructions and untrusted data. Enterprise agents continuously ingest external content (inbound emails, web pages, shared documents, pull requests, and third-party tool outputs) while dynamically invoking privileged tools across the `filesystem`, `shell`, `browser`, `Model Context Protocol` (`MCP`) servers, and `Microsoft Graph` APIs [905, 906]. Because an `LLM` processes developer system instructions, user intent, and untrusted external text inside one shared token context window lacking a hardware-enforced Von Neumann code/data separation, *indirect prompt injection* (`XPIA`) hidden inside untrusted content can steer the model's subsequent tool calls [905].

Viewed through Norman Hardy's 1988 *Confused Deputy* formulation [363], executing an AI agent inside the user's primary Windows desktop session or issuing it an unrestricted user OAuth token is architecturally unsound. If user $u$ holds ambient authority $\mathcal{A}(u)$ over local `DPAPI` vaults, SSH keys, corporate mail, and internal SharePoint sites, and an agent $a$ inherits $\mathcal{A}(u)$ directly while parsing untrusted external input $d$, any adversarial payload embedded inside $d$ exercises $\mathcal{A}(u)$ without exploiting a memory-corruption bug or forging a cryptographic signature [905, 909]. Securing modern workloads and AI agents therefore requires carving agent identity and execution out of the human user's ambient authority domain on both the Windows host and the cloud identity plane.

## Architectural Deep Dive

### On-Box Containment: Windows 11 Agent Workspace, Local Agent SIDs, and LPAC

When desktop-automation or local coding agents run directly inside the user's interactive logon session (`Session 1` under the human user's `Medium-IL` token), they inherit unrestricted read and write access to `%USERPROFILE%`, `%APPDATA%`, unlocked `DPAPI` `MasterKeys` ([Chapter 11](30-data-protection.md)), live browser cookie stores, and local named pipes. To eliminate ambient session sharing, Windows 11's agentic OS architecture interposes four concentric host containment boundaries [901, 906, 907]:

![Figure: Windows 11 agentic containment: interactive user session versus isolated Agent Workspace and signed MCP proxy](diagrams/32-windows-agent-workspace-mcp.svg)

Each of those four containment layers closes a specific local privilege-inheritance channel [901, 906, 907]. Provisioning a dedicated non-interactive local `Agent SID` ensures that kernel `SeAccessCheck` evaluations ([Chapter 10](25-access-control.md)) and `ETW` or Security Event Log records (`4688` process creation and `4663` object access) attribute every file write, socket connection, and child process unambiguously to the agent principal rather than blending autonomous actions into human user activity [901, 907]. Running GUI or Win32 automation inside the separate `Agent Workspace` session enforces User Interface Privilege Isolation (`UIPI`) and desktop-object separation so an agent cannot scrape sensitive windows, inject keystrokes into elevated terminals, or invoke `CryptUnprotectData` against the human user's `DPAPI` secrets, while keeping filesystem visibility deny-by-default outside explicitly delegated Known Folders such as user-approved project directories [907].

Below the session boundary, individual connectors and tool runners execute under `AppContainer` (`S-1-15-2-*`) or `LPAC` tokens [381, 906]. Unlike standard restricted tokens, an `LPAC` token strips the implicit `ALL APPLICATION PACKAGES` (`S-1-15-2-1`) SID, denying read access even to world-readable operating-system and application directories unless an explicit `Capability SID` (`internetClient`, `documentsLibrary`, or a custom named capability) matches the target kernel object's `DACL` [381]. When agent hosts (`VS Code`, Copilot, or custom orchestrators) invoke external tools over `JSON-RPC` via the `Model Context Protocol` (`MCP`), spawning unmediated third-party `MCP` servers as raw `stdio` child processes would reintroduce supply-chain trojans, command injection, and silent post-consent tool mutation. Windows 11 closes that gap by routing calls through the OS `MCP` Proxy Broker and Windows `MCP` Registry, requiring local `MCP` servers to carry valid publisher signatures ([Chapter 7](06-code-integrity.md)) revocable under `App Control` (`WDAC`), declare immutable tool schemas up front, and pass OS-rendered consent and policy checks before touching host capabilities [906].

### Cloud Workload Identities vs. Microsoft Entra Agent ID

In the cloud control plane, Microsoft separates deterministic machine workloads from autonomous and semi-autonomous AI agents across distinct directory object classes [903, 908]. For static Azure microservices, virtual-machine scale sets, and GitHub Actions pipelines whose target APIs are fixed in source code, `Managed Identities for Azure Resources` and `Workload Identity Federation` eliminate exportable client secrets altogether: Azure's platform fabric (`IMDS` at `169.254.169.254` or an external `OIDC` workload issuer) mints short-lived tokens bound to the underlying compute identity and evaluates them under Conditional Access for Workload Identities to enforce trusted network locations and automated risk blocks [903].

Classic `Service Principals` and human `Entra User` accounts both fail, however, when repurposed for AI agents. Because a `Service Principal` was engineered for predictable service-to-service code, granting it static tenant-wide application roles bypasses per-user delegation boundaries, unmanaged registration sprawl leaves orphaned applications active long after their creators change teams, and compromised application credentials can hold Tier-0 directory roles [908]. Conversely, provisioning a standard human `Entra User` account for an agent pollutes human audit telemetry and breaks interactive `MFA` and `WHfB` policies [908].

To resolve that mismatch, `Microsoft Entra Agent ID` introduces a three-object directory governance model tailored specifically to agentic software [908].

![Figure: Microsoft Entra Agent ID three-object governance, OBO intersection, and Conditional Access plane](diagrams/32-entra-agent-id-blueprint.svg)

At the root of this hierarchy sits the `Agent Identity Blueprint`, a parent template that defines the agent class, verified publisher provenance, maximum inheritable permission ceiling, secretless credential rotation policy (brokered via the Entra Auth SDK sidecar without hardcoded credentials), and tenant lifecycle rules [908]. From that template, orchestrators instantiate persistent or task-scoped ephemeral `Agent Identity` runtime objects governed by three platform invariants absent from generic service principals: mandatory human sponsorship at creation (with Entra Governance workflows automatically transferring or suspending orphaned agents when a sponsor departs or changes roles), a hard platform blast-radius ceiling that blocks `Agent Identities` from ever holding Tier-0 administrative roles such as `Global Administrator` or `Privileged Role Administrator`, and automated cascade deletion when ephemeral task instances finish executing [908]. Only when an agent must participate in collaboration workloads whose legacy schemas structurally require a user object, such as owning an `Exchange` mailbox or joining `Teams` threads, does Entra pair a restricted, one-to-one `Agent User` record carrying explicit non-human telemetry markers to its parent `Agent Identity` [908].

### Cryptographic Delegation (`OBO` vs. `Autonomous`) and Policy Enforcement

When an agent acts On-Behalf-Of (`OBO`) a human user $u$ (interactive or delegated mode), issuing the agent an indistinguishable user token violates least privilege. Under `OAuth 2.0 Token Exchange` (`RFC 8693`) and `Entra Agent ID` delegation semantics, the token carries distinct subject (`sub`), authorized party / agent identity (`azp` / `act` actor claim), and narrow resource audience (`aud`) claims [904, 908]. A compliant Policy Enforcement Point (`PEP`) grants access to resource $r$ only under *conjunctive intersection*:

$$\mathrm{Grant}_{\text{OBO}}(u, a, r) \iff \mathrm{Perm}(u, r) \land \mathrm{Scope}(a, r) \land \mathrm{ConditionalAccess}(u, a, \text{risk})$$

An email-summarizer agent invoked by a Chief Financial Officer therefore cannot modify payroll records even though the CFO holds payroll permissions, because `Scope(a, payroll) = false`; conversely, the same agent invoked by an intern cannot read executive board decks even if the agent blueprint supports SharePoint retrieval, because `Perm(intern, board_deck) = false`. When an agent operates in Autonomous (`Non-OBO`) mode without a live human session, dedicated Conditional Access for Agents templates evaluate agent identity risk, blueprint attestation, network boundaries, and `Continuous Access Evaluation` (`CAE`) revocation watermarks [908].

## Attack Catalog & Gap Analysis

Real-world attacks against enterprise workloads and AI agents exploit legacy over-privileged OAuth service principals, cross-boundary prompt-injection paths into shared retrieval contexts, and unmediated local tool connectors.

| Attack / Tool | Year | Boundary Broken | Prerequisite | Adversary Mechanism | Defense / Fix Path |
|---|---|---|---|---|---|
| `Midnight Blizzard` Legacy OAuth Pivot | 2024 | Test tenant OAuth app → Corporate Exchange mail | Compromised legacy test tenant credential | Abused legacy test OAuth app to provision malicious service principals granted `full_access_as_app` on Exchange Online [840, 841] | Decommission unused apps (`1.4M` retired under SFI), enforce Workload CA, and gate app role grants [912] |
| Illicit OAuth Consent Phishing | 2020-present | User MFA / passkey bypass via delegated OAuth grant | Victim tricked into clicking `/authorize` consent link | Tricks user into granting attacker multi-tenant app `Mail.Read` / `Files.ReadWrite.All` refresh tokens without stealing password [903] | Restrict user consent to verified publishers + admin consent workflows in Entra ID |
| `EchoLeak` (`CVE-2025-32711`) | 2025 | Zero-click external email → M365 Copilot tenant exfiltration | Ability to send external email to target mailbox | Indirect prompt injection (`XPIA`) evades classifier during RAG indexing, pulls internal M365 context, and auto-exfiltrates via allowed URL/image rendering [909] | Enforce strict egress/CSP origin locks, scope isolation between external/internal RAG tiers, and deterministic output filters [909] |
| Ambient-Session Desktop Agent `XPIA` | 2024-2026 | Untrusted web/doc content → User `DPAPI` & local files | Agent running in user's primary Windows session | Hidden DOM/document instructions steer computer-use or coding agent to read `~/.ssh`, `.env`, or cookies and POST outward [905, 907] | Run agents strictly inside Windows 11 `Agent Workspace` under a separate local Agent `SID` + `LPAC` [907] |
| `MCP` Tool Poisoning & Rug-Pulls | 2025-2026 | Trusted MCP host → Arbitrary local RCE / secret leak | Unsigned or mutable third-party `MCP` server | Embeds hidden prompt instructions inside MCP tool JSON `description` metadata or mutates tool behavior post-consent [906] | Enforce signed servers via Windows `MCP` Registry/Proxy, `WDAC` publisher pinning, and schema hash locking [906] |
| Orphaned Workload Secrets & Over-Scoped `SPNs` | 2019-present | Stale CI/CD secret → Persistent cloud lateral movement | Leaked client secret in repo/build log | Replays long-lived `client_secret` of ownerless `Service Principal` bypassing human MFA and password rotation [903, 908] | Replace secrets with `Managed Identities` / `OIDC` federation and migrate agents to `Entra Agent ID` with enforced sponsors [908] |

### Gap Analysis: EchoLeak (`CVE-2025-32711`) and the Confused-Deputy Anatomy

Disclosed by Aim Labs in June 2025, `EchoLeak` (`CVE-2025-32711`) demonstrated the first zero-click indirect prompt injection exfiltration chain against an enterprise production AI assistant (`Microsoft 365 Copilot`) [909].

![Figure: Indirect prompt injection as a confused-deputy chain in EchoLeak CVE-2025-32711](diagrams/32-agent-confused-deputy-xpia.svg)

The exploit unfolded across three coupled architectural seams without requiring the target employee to click any link or approve any consent prompt. First, an unauthenticated external sender delivered a routine-looking email to the victim's corporate inbox carrying concealed adversarial instructions carefully phrased without conventional jailbreak tokens so inbound `XPIA` classifiers passed the message into the index [909]. Later, when the employee asked Copilot an ordinary workplace question, Copilot's Retrieval-Augmented Generation (`RAG`) pipeline pulled both the untrusted external email and sensitive internal SharePoint and OneDrive documents into the same `LLM` context window under the user's delegated `OBO` Microsoft Graph permissions [909]. Although outbound Content Security Policy (`CSP`) rules blocked arbitrary third-party image origins, the injected instructions steered the model to encode confidential internal context as query parameters inside an auto-fetched trusted-domain proxy URL (`SharePoint` and `Teams` link-preview and reference-style Markdown rendering), silently transmitting tenant secrets out to the attacker's infrastructure [909].

`EchoLeak` demonstrates why statistical prompt-injection classifiers (`XPIA` filters) remain valuable defense-in-depth yet *cannot serve as a primary security boundary*: the structural failure lay not in imperfect natural-language filtering, but in allowing a single execution context to combine *untrusted external input*, *broad internal data access*, and *an unconstrained outbound side channel* [905, 909].

> **Key idea.**
> Because an LLM processes instructions and untrusted data in one shared representation without a formal grammar boundary, natural-language prompt filtering cannot guarantee isolation. Sound agentic architecture assumes the model itself can be subverted by untrusted context and enforces hard security boundaries outside the model: distinct OS `Agent SIDs` and `LPAC` sandboxes on the host, `OBO` permission intersection (`Perm(User) AND Scope(Agent)`) in the token, and deterministic egress allowlists on the network.

## Theoretical Limits & Structural Invariants

### Non-Separability of Natural-Language Instructions and Data

Because a transformer maps arbitrary token sequences into continuous latent representations without a formal lexical or hardware boundary separating instructions from passive data, deciding whether an arbitrary natural-language or multimodal document will steer model generation toward an adversary's objective is non-separable in general [905]. System prompts and classifier guardrails reduce opportunistic abuse, yet deterministic containment must be enforced outside the neural network by operating-system reference monitors (`Agent SIDs`, `Agent Workspace` session isolation, and `LPAC` capability DACLs), cryptographic token narrowing, and strict network egress allowlists.

### Monotonicity of Delegation and Distinct Principal Attribution

Safe delegation obeys strict capability monotonicity ($\mathcal{A}_{\text{effective}} \subseteq \mathcal{A}_{\text{caller}} \cap \mathcal{A}_{\text{agent}}$): no agent invocation may amplify authority beyond the invoking human's own permissions (*privilege escalation*) or beyond the agent blueprint's declared task scope (*confused deputy*), while autonomous non-human runs without a live user session must remain bounded to blueprint-scoped roles disjoint from Tier-0 directory administration [908]. Preserving forensic non-repudiation across those runs simultaneously requires distinct principal attribution. Whenever an agent shares a human user's local `SID` on Windows or user `oid` in cloud logs, incident responders lose the ability to distinguish insider malice, endpoint compromise, and prompt-injected agent execution; dedicated `Local Agent SIDs` and `Entra Agent IDs` preserve unambiguous causal provenance across both `ETW` and Entra audit trails [901, 908].

## Inspecting and Verifying on a Running System

Practitioners verify local and cloud workload containment by auditing local Windows user accounts and `AppContainer` firewall filters on the endpoint alongside exportable credentials and high-privilege `AppRole` assignments across `Microsoft Entra ID`.

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

Non-human workloads and AI agents extend the Windows trust chain beyond interactive human sessions on both the client endpoint and the cloud directory. On a Windows 11 host, `Agent Workspace` session separation, dedicated local `Agent SIDs`, `LPAC` capability tokens, and signed `MCP` proxy mediation strip autonomous tools of ambient access to the user's primary desktop and `DPAPI` vaults. In the cloud, `Managed Identities` and `OIDC` workload federation retire static service secrets while `Microsoft Entra Agent ID` binds AI agents to sponsor-governed blueprints, conjunctive `OBO` permission intersections, Tier-0 directory-role blocks, and dynamic `Conditional Access` and `CAE` session governance.

Every cloud service and agent control plane examined from Chapter 19 through Chapter 21, however, still executes on physical datacenter servers operated by a public cloud provider. [Confidential VMs](29-confidential-vms.md) (Chapter 22) addresses that underlying infrastructure boundary, showing how `AMD SEV-SNP` and `Intel TDX` silicon memory encryption paired with `OpenHCL` `vTPM` remote attestation exclude even a compromised cloud host hypervisor from workload memory, before [When the Chain Snaps: Storm-0558](15-storm0558.md) (Chapter 23) examines how a stolen root signing key and an omitted cross-tier issuer check bypassed the entire chain from above.
