#!/usr/bin/env node
/**
 * Generates the flagship sunlit Apple-product-page-grade interactive Series Showcase
 * at both `book/index.html` (root `/trust-chain/`) and `book/series/index.html`
 * (`/trust-chain/series/`).
 */
import { writeFileSync, mkdirSync } from 'node:fs';
import path from 'node:path';

function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const VOLUME_SHOWCASE = {
  windows: {
    eyebrow: 'Volume I · Enterprise & Hypervisor Architecture',
    headline: 'Thirty years of compatibility, retrofitted above silicon.',
    blurb:
      'Traces how Windows anchors trust in Boot Guard, UEFI, TPM 2.0, and Pluton, carves Virtual Trust Level 1 out of guest memory via Hyper-V SLAT to shield LSASS and HVCI, retires NTLM across Kerberos and AD CS, and extends attestation to Agent Workspaces and Confidential VMs.',
    parts: [
      'Silicon: UEFI, TPM 2.0, Pluton, Attestation',
      'Kernel: VBS/VTL1, HVCI/WDAC, PPL, CET/CFG',
      'Identity: Tokens, DPAPI, Cred Guard, Kerberos, PKI, Passkeys',
      'Cloud & AI: ETW, Zero Trust, CAE, Agent IDs, CVMs, Storm-0558',
    ],
    inkHex: '#946200',
    dotHex: '#c88a12',
    foilHex: '#d4a843',
    rgb: '180, 122, 14',
    alcoveTint: 'linear-gradient(155deg, #f6f3eb 0%, #ede7d9 100%)',
  },
  apple: {
    eyebrow: 'Volume II · Unified Apple Silicon to Zero-Knowledge Cloud',
    headline: 'Five operating systems. One silicon-personalized spine.',
    blurb:
      'Follows the unified Darwin chain across iOS, iPadOS, macOS, watchOS, and visionOS: Boot ROM and per-ECID Image4 personalization, the macOS 1TR LocalPolicy fork, Secure Enclave UID fuses, SPTM and A19/M5 Memory Integrity Enforcement (EMTE), BlastDoor, TCC, iCloud ADP, PQ3, App Intents, and Private Cloud Compute.',
    parts: [
      'Silicon: Boot ROM, Image4/TSS, 1TR LocalPolicy, SEP, SPTM & EMTE',
      'XNU & Sandbox: APFS SSV, AMFI/TXM, XPC, Seatbelt, BlastDoor, TCC',
      'Custody & Fleet: BFU/AFU, Stolen Device, App Attest/MDA, DDM/PSSO',
      'Cloud & AI: HSM Escrow/ADP, PQ3/KT, Find My, App Intents, PCC',
    ],
    inkHex: '#0066cc',
    dotHex: '#0071e3',
    foilHex: '#7cc4f8',
    rgb: '0, 113, 227',
    alcoveTint: 'linear-gradient(155deg, #eef4fb 0%, #e2ecf7 100%)',
  },
  linux: {
    eyebrow: 'Volume III · Composable Open-Source Primitives & Supply Chain',
    headline: 'Assembled from open parts. Tested at every seam.',
    blurb:
      'Examines how modern Linux closes the historic initramfs and SUID gaps via shim/SBAT, Unified Kernel Images, and systemd-pcrlock TPM2 policies, enforces runtime integrity with dm-verity, IPE, stacked LSMs, and eBPF, isolates AI code-execution sandboxes inside gVisor and Firecracker, and confronts XZ Utils upstream subversion.',
    parts: [
      'Verified Boot: UEFI shim/SBAT, UKI, systemd-pcrlock, dm-verity, IPE',
      'Kernel & eBPF: Lockdown, KCFI/Rust, SELinux, AppArmor, Landlock, BPF',
      'Userspace: Capabilities/userns, systemd run0, systemd-creds, OpenSSH',
      'Cloud & Supply Chain: OCI, gVisor/Firecracker AI, SPIFFE, SVSM/CoCo, XZ',
    ],
    inkHex: '#b34d00',
    dotHex: '#d96518',
    foilHex: '#e5954b',
    rgb: '217, 101, 24',
    alcoveTint: 'linear-gradient(155deg, #f8f1eb 0%, #efe4d8 100%)',
  },
  android: {
    eyebrow: 'Volume IV · Zero-Ambient-Session Mobile Isolation',
    headline: 'Linux inverted into a capability-like mobile computer.',
    blurb:
      'Dissects how Android eliminates ambient user sessions across a multi-vendor SoC ecosystem: AVB 2.0 VBMeta and RPMB rollback floors, Titan M2 StrongBox and Weaver throttling, EL2 Protected KVM (pKVM) de-privileging both Linux and TrustZone, universal SELinux neverallow gates, Arm MTE, RKP Key Attestation, Intrusion Logging, and Private AI Compute.',
    parts: [
      'Silicon & Boot: Lock States, AVB 2.0 VBMeta, APEX, StrongBox/KeyMint',
      'Kernel & MTE: EL2 pKVM (AVF/DICE), SELinux neverallow, GKI/Rust, MTE',
      'Sandbox & Data: Per-App UID/Binder, Advanced Protection, FBE, Passkeys',
      'Attestation & AI: Intrusion Logs, RKP vs. Keyboxes, AICore, Private AI',
    ],
    inkHex: '#0b7a4b',
    dotHex: '#169c63',
    foilHex: '#57c98c',
    rgb: '22, 156, 99',
    alcoveTint: 'linear-gradient(155deg, #edf6f2 0%, #e0efe8 100%)',
  },
};

const STACK_LAYERS = [
  {
    num: '01',
    short: 'Silicon & Boot Root',
    title: 'Reset Vector, Immutable Silicon, and Cryptographic Boot',
    summary:
      'Before an operating system kernel exists to defend itself, immutable on-die ROM and fused root keys must authenticate every firmware and bootloader stage while preventing version rollback.',
    os: {
      windows: {
        prims: ['Boot Guard / PSB', 'UEFI db / dbx', 'Pluton', 'PCR[0..7]'],
        invariant: 'LoadImage() rejects any PE bootloader in dbx or absent from db; Trusted Boot validates winload.efi and ntoskrnl.exe.',
        breakCase: 'BlackLotus (CVE-2022-21894) replaying unrevoked 2011-signed bootmgfw.efi; LogoFAIL DXE parser heap corruption.',
      },
      apple: {
        prims: ['Boot ROM', 'Image4 (IM4M)', 'TSS + ECID', '1TR LocalPolicy'],
        invariant: 'Per-ECID + ephemeral ApNonce TSS signatures prevent fleet-wide replay; macOS downgrades require physical 1TR + SEP owner auth.',
        breakCase: 'checkm8 (CVE-2019-8900) and usbliter8 unpatchable USB DFU bugs in mask ROM, bounded by SEP UID isolation.',
      },
      linux: {
        prims: ['shim.efi + MOK', 'SBAT', 'UKI (.linux+.initrd)', 'systemd-pcrlock'],
        invariant: 'Authenticode-signed UKI binds kernel, cmdline, and initrd into one PE binary measured into TPM 2.0 PCR[11] phase policies.',
        breakCase: 'Unmeasured legacy initramfs hooks; BootHole GRUB2 overflows; shim HTTP boot RCE (CVE-2023-40547).',
      },
      android: {
        prims: ['SoC PBL Fuses', 'AVB 2.0 VBMeta', 'RPMB Rollback', 'dm-verity FEC'],
        invariant: 'Root VBMeta verifies chained partition descriptors and enforces monotonic RPMB anti-rollback counters before mounting /system.',
        breakCase: 'Leaked Qualcomm EDL Firehose programmers and vendor fastboot state-machine unlock bypasses.',
      },
    },
  },
  {
    num: '02',
    short: 'Monitors & Memory',
    title: 'Hypervisor Rings, Lateral Monitors, and Hardware Memory Tagging',
    summary:
      'Because monolithic kernels expose millions of lines of C to untrusted callers, modern platforms strip page-table and secret authority out of Ring 0 / EL1 into higher hardware privilege planes.',
    os: {
      windows: {
        prims: ['Hyper-V SLAT', 'VBS (VTL0 / VTL1)', 'HVCI W^X', 'CET + kCFG'],
        invariant: 'Second-Level Address Translation blocks compromised VTL0 Ring 0 drivers from reading VTL1 LsaIso secrets or mapping unsigned RWX kernel pages.',
        breakCase: 'BYOVD vulnerable signed drivers in VTL0 when HVCI is disabled; BCD boot-configuration tampering.',
      },
      apple: {
        prims: ['SPTM (GL2)', 'TXM (GL0)', 'ARM PAC', 'A19/M5 EMTE (MIE)'],
        invariant: 'Orthogonal Guarded Execution owns physical frame types above XNU; synchronous EMTE + tag confidentiality enforce deterministic heap bounds.',
        breakCase: 'Operation Triangulation (CVE-2023-38606) undocumented MMIO DMA bypass; PACMAN speculative signing oracle.',
      },
      linux: {
        prims: ['Kernel Lockdown', 'KCFI / FineIBT', 'CET Shadow Stack', 'SLAB_VIRTUAL + Rust'],
        invariant: 'Lockdown severs UID 0 from Ring 0 (/dev/mem, kexec, unsigned .ko); virtual slab quarantine blocks cross-cache page-table reuse.',
        breakCase: 'Dirty Pagetable cross-cache UAFs via msg_msg/pipe_buffer; EntryBleed prefetch KASLR side channel.',
      },
      android: {
        prims: ['EL2 pKVM (AVF)', 'OpenProfile DICE', 'Titan M2 StrongBox', 'Arm MTE + Scudo'],
        invariant: 'pKVM Stage-2 hyp_vmemmap ownership revokes host Linux access to donated Microdroid guest frames; StrongBox isolates keys off-SoC.',
        breakCase: 'Legacy TrustZone QSEE/Kinibi trustlet overflows; TIKTAG speculative MTE tag-probing gadgets.',
      },
    },
  },
  {
    num: '03',
    short: 'Code & Containment',
    title: 'Code Signing, Mandatory Access Control, and Parser Quarantine',
    summary:
      'Every process launch and cross-process call must bind code provenance to fine-grained object capabilities rather than ambient human user accounts.',
    os: {
      windows: {
        prims: ['App Control (WDAC)', 'PPL Signer Lattice', 'MIC Integrity Levels', 'AppContainer'],
        invariant: 'SeAccessCheck enforces Mandatory Integrity Control before DACLs; PPL blocks even SYSTEM admins from opening protected lsass/EDR handles.',
        breakCase: 'SeImpersonatePrivilege named-pipe Potato escalations; unblocked user-writable WDAC script/LOLBin hosts.',
      },
      apple: {
        prims: ['APFS SSV + Cryptex', 'AMFI / Launch Constr.', 'Seatbelt + XPC', 'BlastDoor + TCC'],
        invariant: 'TXM enforces per-page CDHash trust caches and DER Launch Constraints; XPC audit_token_t and BlastDoor isolate zero-click message parsers.',
        breakCase: 'FORCEDENTRY JBIG2 logic circuit; dyld CVE-2026-20700; macOS TCC responsible_pid and HM Surf (CVE-2024-44133) bypasses.',
      },
      linux: {
        prims: ['IPE + fs-verity', 'SELinux / AppArmor', 'Landlock ABI v7', 'systemd run0'],
        invariant: 'Stacked LSMs mediate inode and socket hooks; unprivileged Landlock self-sandboxes processes while run0 eliminates SUID binaries.',
        breakCase: 'Unprivileged user_namespaces + nf_tables (CVE-2024-1086) / Dirty Pipe; PwnKit & sudo chroot (CVE-2025-32463).',
      },
      android: {
        prims: ['Per-App AID_* UID', 'SELinux neverallow', 'Kernel Binder IPC', 'Advanced Protection'],
        invariant: 'Every APK runs in an isolated UID and MLS SELinux category enforced by CTS neverallow tests; Binder mediates unforgeable object handles.',
        breakCase: 'Parcel read/write mismatches; CVE-2019-2215 Binder UAF; social-engineered AccessibilityService banking trojans.',
      },
    },
  },
  {
    num: '04',
    short: 'Telemetry & Forensics',
    title: 'Runtime Observability Across Open Desktops and Locked Handsets',
    summary:
      'Defenders can only catch chain breaks they can observe without creating new privilege-escalation or privacy-surveillance surfaces in the telemetry plane itself.',
    os: {
      windows: {
        prims: ['Kernel ETW', 'EtwTi (PPL Threat-Intel)', 'AMSI', 'Autologgers'],
        invariant: 'Kernel EtwTi emits unpatchable memory/process telemetry exclusively to Antimalware-PPL subscribers signed under Microsoft flight roots.',
        breakCase: 'User-mode ntdll!EtwEventWrite patching; BYOVD kernel callback array zeroing when HVCI is off.',
      },
      apple: {
        prims: ['EndpointSecurity (ESF)', 'XProtect + Bastion', 'Unified Logging', 'iOS sysdiagnose'],
        invariant: 'macOS replaces Ring 0 kexts with deadline-bounded ESF AUTH/NOTIFY clients; locked iOS bans third-party EDR in favor of forensic artifacts.',
        breakCase: 'ESF AUTH deadline starvation or default mute-set blind spots; ephemeral RAM-only implants evading reboot.',
      },
      linux: {
        prims: ['LSM-BPF (KRSI)', 'eBPF Ring Buffers', 'Tetragon / Falco', 'IMA / auditd'],
        invariant: 'Verifier-checked LSM-BPF hooks enforce synchronous atomic policy on kernel objects without TOCTOU path re-resolution races.',
        breakCase: 'eBPF verifier tnum ALU32 bounds escapes (CVE-2021-3490); bpf_probe_write_user user-memory tampering.',
      },
      android: {
        prims: ['Play Protect ML', 'Dynamic Signal Mon.', 'DPM SecurityLog', 'E2EE Intrusion Logs'],
        invariant: 'Android 16/17 streams forward-secure E2EE Intrusion Logs to cloud vaults so post-compromise root spyware cannot erase local evidence.',
        breakCase: 'Icon-hiding staged session droppers delaying payload activation until post-install Play scan completes.',
      },
    },
  },
  {
    num: '05',
    short: 'Custody & Identity',
    title: 'At-Rest Encryption, Hardware Key Attestation, and Phishing-Proof Auth',
    summary:
      'Cryptographic secrets must bind mathematically to verified device posture and origin-scoped WebAuthn ceremonies rather than replayable passwords or bearer hashes.',
    os: {
      windows: {
        prims: ['BitLocker + TPM PIN', 'DPAPI / CNG KeyIso', 'Cred Guard + dMSA', 'PRT + Hello Passkeys'],
        invariant: 'TPM-bound Primary Refresh Tokens and WebAuthn origin binding eliminate replayable NTLM hashes and cross-origin credential phishing.',
        breakCase: 'Bitpixie PXE soft-reboot VMK sniff on TPM-only BitLocker; AD CS ESC1 template SAN spoofing; stolen session cookies.',
      },
      apple: {
        prims: ['APFS Classes A-D', '72h BFU Auto-Reboot', 'Stolen Device Prot.', 'App Attest + ACME MDA'],
        invariant: 'Per-file keys wrap under SEP UID + user passcode; Stolen Device Protection enforces biometric-only + 1h delay away from familiar locations.',
        breakCase: 'macOS legacy login.keychain-db ambient access abused by AMOS/DarkSword stealers; CVE-2025-24200 locked USB bypass.',
      },
      linux: {
        prims: ['Kernel Keyrings', 'systemd-creds (TPM2)', 'OpenSSH Certs + FIDO2', 'SPIFFE / SPIRE'],
        invariant: 'systemd-creds hybrid-seals service secrets to host key + TPM2 PCR[7,11]; SPIRE attests kernel/cgroup workload identity for short-lived SVIDs.',
        breakCase: 'Unencrypted /etc secrets; SSH_AUTH_SOCK agent-forwarding hijack; OpenSSH regreSSHion (CVE-2024-6387) SIGALRM RCE.',
      },
      android: {
        prims: ['fscrypt v2 Inline ICE', 'Weaver + Identity Check', 'X.509 Key Attestation', 'Remote Key Prov. (RKP)'],
        invariant: 'Inline UFS crypto keeps raw FBE keys out of DRAM; RKP rotates short-lived DICE-anchored attestation certs replacing static factory keys.',
        breakCase: 'Cellebrite USB audio/video zero-days (CVE-2024-53197) in AFU state; TrickyStore spoofing leaked OEM keyboxes.',
      },
    },
  },
  {
    num: '06',
    short: 'Cloud, AI, & Seams',
    title: 'Confidential Cloud TEEs, Agentic AI Sandboxes, and Catastrophic Breaks',
    summary:
      'At the apex of the chain, device trust extends into remote-attested cloud enclaves and autonomous AI agents, where confused deputies and upstream supply chains test every assumption.',
    os: {
      windows: {
        prims: ['Conditional Access + CAE', 'Agent Workspace + SIDs', 'Entra Agent ID', 'Azure CVM (SEV-SNP/TDX)'],
        invariant: 'Distinct local Agent SIDs and Entra Agent Blueprints bound autonomous MCP tools; hardware memory encryption removes the cloud host from TCB.',
        breakCase: 'Storm-0558 MSA signing-key crash-dump theft + validation bypass; Battering RAM DDR interposers; XPIA confused deputies.',
      },
      apple: {
        prims: ['iCloud HSM + ADP', 'iMessage PQ3 + KT', 'App Intents + .onToolCall', 'Private Cloud Compute'],
        invariant: 'Stateless RAM-only Apple Silicon PCC nodes require public Transparency Log inclusion proofs before Thimble releases encrypted prompts.',
        breakCase: 'macOS MCP agents inheriting Terminal TCC Full Disk Access; UK IPA Section 253 sovereign compulsion forcing UK ADP withdrawal.',
      },
      linux: {
        prims: ['gVisor + Firecracker', 'Landlock + Cred Proxy', 'COCONUT-SVSM (VMPL0)', 'Confidential Containers'],
        invariant: 'Ephemeral micro-VMs with credential-injecting egress proxies isolate untrusted LLM code; Kata Rego policies block host kubelet exec.',
        breakCase: 'XZ Utils (CVE-2024-3094) release-tarball + GNU_IFUNC sshd backdoor subverting binaries upstream of Secure Boot.',
      },
      android: {
        prims: ['AICore + Private Compute', 'Gemini AppFunctions', 'Secure Virtual Window', 'Private AI Compute (TIE)'],
        invariant: 'SELinux neverallow strips network access from Private Compute Core; Titanium Intelligence Enclaves attest custom cloud TPUs end to end.',
        breakCase: 'Zero-click Exynos/Shannon VoLTE baseband RCE (CVE-2023-24033); Mali/Adreno GPU UAFs across the multi-vendor OEM patch gap.',
      },
    },
  },
];

export function renderSeriesPortalHtml(registry, rootRel = '') {
  const canonicalUrl = rootRel
    ? `${registry.siteUrl}/series/`
    : `${registry.siteUrl}/`;
  const ogImage = `${registry.siteUrl}/windows/cover.png`;
  const gaId = registry.gaMeasurementId || '';

  const gaScript = gaId
    ? `<script>
(function () {
  if (location.protocol !== 'https:' || location.hostname === 'localhost' || location.hostname === '127.0.0.1') return;
  var s = document.createElement('script');
  s.async = true;
  s.src = 'https://www.googletagmanager.com/gtag/js?id=${esc(gaId)}';
  document.head.appendChild(s);
  window.dataLayer = window.dataLayer || [];
  function gtag() { window.dataLayer.push(arguments); }
  window.gtag = gtag;
  gtag('js', new Date());
  gtag('config', '${esc(gaId)}', { book_volume: 'series_showcase' });
  document.addEventListener('click', function (e) {
    var a = e.target && e.target.closest ? e.target.closest('a[href]') : null;
    if (!a) return;
    var href = a.getAttribute('href') || '';
    if (/\\.pdf($|\\?|#)/i.test(href)) {
      gtag('event', 'pdf_download', { book_volume: a.getAttribute('data-vol') || 'series', file_url: href });
    }
  });
})();
</script>`
    : '';

  const jsonLd = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'BookSeries',
    name: registry.seriesTitle,
    description: registry.seriesSubtitle,
    url: `${registry.siteUrl}/`,
    author: { '@type': 'Person', name: registry.author, url: 'https://paragmali.com' },
    hasPart: registry.volumes.map((v) => ({
      '@type': 'Book',
      name: v.title,
      url: `${registry.siteUrl}/${v.mount}/`,
      numberOfPages: v.pages,
      inLanguage: 'en',
    })),
  });

  // Hero 3D shelf items resting on sunlit studio plinth
  const shelfAngles = [-10, -3.4, 3.4, 10];
  const shelfY = [14, 2, 2, 14];
  const heroBooksHtml = registry.volumes
    .map((v, idx) => {
      const meta = VOLUME_SHOWCASE[v.slug];
      const bookHref = `${rootRel}${v.mount}/index.html`;
      const coverSrc = `${rootRel}${v.mount}/cover.png`;
      return `
        <a class="shelf-book tilt-stage" href="${bookHref}" data-idx="${idx}"
           style="--base-ry:${shelfAngles[idx]}deg; --base-ty:${shelfY[idx]}px; --vol-rgb:${meta.rgb}; --vol-ink:${meta.inkHex}; --vol-foil:${meta.foilHex};"
           aria-label="Read ${esc(v.title)} (${v.pages} pages)">
          <div class="book-3d">
            <div class="book-front">
              <img src="${coverSrc}" alt="${esc(v.title)} Front Cover" width="700" height="925" decoding="async">
              <div class="book-crease"></div>
              <div class="book-sheen"></div>
            </div>
            <div class="book-spine">
              <span class="spine-vol">${esc(v.volume.toUpperCase())}</span>
              <span class="spine-title">${esc(v.title.toUpperCase())}</span>
            </div>
            <div class="book-pages"></div>
            <div class="book-back"></div>
          </div>
          <div class="book-floor-shadow"></div>
          <div class="shelf-caption">
            <span class="shelf-vol-pill">${esc(v.volume)} &middot; ${esc(v.shortName)}</span>
            <span class="shelf-metrics">${v.chapters} Ch &middot; ${v.pages} pp</span>
          </div>
        </a>`;
    })
    .join('\n');

  // Sculpted daylight showcase cards with recessed photography alcoves
  const volumeCardsHtml = registry.volumes
    .map((v) => {
      const meta = VOLUME_SHOWCASE[v.slug];
      const readHref = `${rootRel}${v.mount}/index.html`;
      const pdfHref = `${rootRel}${v.mount}/${v.pdfFile}`;
      const coverSrc = `${rootRel}${v.mount}/cover.png`;
      const partsHtml = meta.parts
        .map((p) => `<div class="spec-part-item"><span class="spec-dot"></span><span>${esc(p)}</span></div>`)
        .join('');
      return `
        <article class="vol-showcase elevated-card reveal" style="--vol-rgb:${meta.rgb}; --vol-ink:${meta.inkHex}; --vol-dot:${meta.dotHex}; --vol-foil:${meta.foilHex}; --alcove-bg:${meta.alcoveTint};">
          <div class="vol-visual-alcove tilt-stage">
            <a class="showcase-book-stage" href="${readHref}" tabindex="-1" aria-hidden="true">
              <div class="book-3d showcase-3d">
                <div class="book-front">
                  <img src="${coverSrc}" alt="${esc(v.title)} cover" loading="lazy" width="700" height="925">
                  <div class="book-crease"></div>
                  <div class="book-sheen"></div>
                </div>
                <div class="book-spine">
                  <span class="spine-vol">${esc(v.volume.toUpperCase())}</span>
                  <span class="spine-title">${esc(v.title.toUpperCase())}</span>
                </div>
                <div class="book-pages"></div>
                <div class="book-back"></div>
              </div>
              <div class="book-floor-shadow showcase-shadow"></div>
            </a>
          </div>
          <div class="vol-copy-col">
            <div class="vol-eyebrow">${esc(meta.eyebrow)}</div>
            <h3 class="vol-title">${esc(v.title)}</h3>
            <p class="vol-subheadline">${esc(meta.headline)}</p>
            <p class="vol-blurb">${esc(meta.blurb)}</p>
            <div class="spec-parts-list">
              ${partsHtml}
            </div>
            <div class="vol-stat-strip" aria-label="Volume specifications">
              <div><strong>${v.chapters}</strong><span>Chapters</span></div>
              <div><strong>${v.pages}</strong><span>Print Pages</span></div>
              <div><strong>${v.figures}</strong><span>SVG Figures</span></div>
              <div><strong>${v.sources}</strong><span>Sources</span></div>
            </div>
            <div class="vol-actions">
              <a class="btn-primary" href="${readHref}">
                <span>Read Web Edition</span>
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M3.5 8h9M8.5 4l4 4-4 4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
              </a>
              <a class="btn-secondary" href="${pdfHref}" data-vol="${v.slug}">
                <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 2.5v7.5M5 7.5L8 10.5l3-3M3 13h10" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/></svg>
                <span>PDF Edition (${esc(v.pdfSize)})</span>
              </a>
            </div>
          </div>
        </article>`;
    })
    .join('\n');

  const stackButtonsHtml = STACK_LAYERS.map(
    (l, i) => `
      <button class="tier-btn${i === 0 ? ' active' : ''}" type="button" data-tier="${i}" role="tab" aria-selected="${i === 0 ? 'true' : 'false'}">
        <span class="tier-num">${l.num}</span>
        <span class="tier-label">${esc(l.short)}</span>
        <span class="tier-progress"><span class="tier-progress-fill"></span></span>
      </button>`
  ).join('\n');

  const stackDataJson = JSON.stringify(
    STACK_LAYERS.map((l) => ({
      ...l,
      links: {
        windows: `${rootRel}windows/index.html`,
        apple: `${rootRel}apple/index.html`,
        linux: `${rootRel}linux/index.html`,
        android: `${rootRel}android/index.html`,
      },
    }))
  );

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
  <title>${esc(registry.seriesTitle)} - ${esc(registry.author)}</title>
  <meta name="description" content="Four complete, primary-source systems security monographs (Windows, Apple, Linux, Android; 1,457 pages, 266 vector figures, 2,587 sources) tracing verifiable trust from silicon reset vectors to confidential cloud and agentic AI.">
  <meta name="author" content="${esc(registry.author)}">
  <meta name="theme-color" content="#fbfbfd">
  <link rel="canonical" href="${esc(canonicalUrl)}">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="${esc(registry.seriesTitle)}">
  <meta property="og:title" content="${esc(registry.seriesTitle)}">
  <meta property="og:description" content="${esc(registry.seriesSubtitle)}">
  <meta property="og:url" content="${esc(canonicalUrl)}">
  <meta property="og:image" content="${esc(ogImage)}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:title" content="${esc(registry.seriesTitle)}">
  <meta name="twitter:description" content="${esc(registry.seriesSubtitle)}">
  <meta name="twitter:image" content="${esc(ogImage)}">
  <script type="application/ld+json">${jsonLd}</script>
  ${gaScript}
  <style>
    :root {
      color-scheme: light;
      --bg-canvas: #fbfbfd;
      --bg-grouped: #f5f5f7;
      --bg-card: #ffffff;
      --bg-recessed: #f0f2f6;
      --ink-1: #1d1d1f;
      --ink-2: #515154;
      --ink-3: #86868b;
      --hairline: rgba(15, 23, 42, 0.08);
      --border-card: rgba(15, 23, 42, 0.07);
      --ease-out-expo: cubic-bezier(0.16, 1, 0.3, 1);
      --ease-spring: cubic-bezier(0.22, 1, 0.36, 1);
      --sans: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", Inter, system-ui, sans-serif;
      --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
      --shadow-card:
        0 1px 2px rgba(15, 23, 42, 0.03),
        0 10px 26px -8px rgba(15, 23, 42, 0.065),
        0 28px 60px -18px rgba(15, 23, 42, 0.085);
      --shadow-card-hover:
        0 2px 6px rgba(15, 23, 42, 0.045),
        0 18px 38px -10px rgba(15, 23, 42, 0.10),
        0 40px 80px -20px rgba(15, 23, 42, 0.13);
    }

    *, *::before, *::after { box-sizing: border-box; }
    html {
      scroll-behavior: smooth;
      background: var(--bg-canvas);
      color: var(--ink-1);
      font-family: var(--sans);
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      text-rendering: optimizeLegibility;
    }
    body {
      margin: 0;
      background: var(--bg-canvas);
      overflow-x: hidden;
    }
    a { color: inherit; text-decoration: none; }
    button { font-family: inherit; }

    /* === Sticky Frosted-Milk Daylight Apple Local Nav === */
    .local-nav {
      position: sticky;
      top: 0;
      z-index: 100;
      height: 52px;
      background: rgba(251, 251, 253, 0.80);
      backdrop-filter: saturate(180%) blur(22px);
      -webkit-backdrop-filter: saturate(180%) blur(22px);
      border-bottom: 1px solid rgba(15, 23, 42, 0.075);
      transition: box-shadow 0.25s ease;
    }
    .local-nav.scrolled {
      box-shadow: 0 4px 20px rgba(15, 23, 42, 0.05);
    }
    .local-nav-inner {
      max-width: 1200px;
      height: 100%;
      margin: 0 auto;
      padding: 0 24px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
    }
    .brand-lockup {
      display: inline-flex;
      align-items: center;
      gap: 10px;
      font-size: 0.91rem;
      font-weight: 600;
      letter-spacing: -0.016em;
      color: var(--ink-1);
    }
    .brand-die {
      width: 21px;
      height: 21px;
      border-radius: 6px;
      background: linear-gradient(145deg, #2c2c30, #141416);
      display: grid;
      place-items: center;
      box-shadow:
        inset 0 1px 0 rgba(255,255,255,0.25),
        0 2px 5px rgba(15, 23, 42, 0.20);
    }
    .brand-die::after {
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 2px;
      background: #fbfbfd;
    }
    .nav-links {
      display: flex;
      align-items: center;
      gap: 28px;
      font-size: 0.80rem;
      color: var(--ink-2);
      letter-spacing: -0.006em;
    }
    .nav-links a { transition: color 0.2s ease; }
    .nav-links a:hover { color: var(--ink-1); }
    .nav-cta-group {
      display: flex;
      align-items: center;
      gap: 16px;
    }
    .nav-gh {
      font-size: 0.79rem;
      color: var(--ink-2);
      transition: color 0.2s ease;
    }
    .nav-gh:hover { color: var(--ink-1); }
    .nav-pill {
      padding: 6px 15px;
      border-radius: 980px;
      background: #1d1d1f;
      color: #ffffff;
      font-size: 0.76rem;
      font-weight: 600;
      letter-spacing: -0.01em;
      box-shadow: 0 2px 6px rgba(15, 23, 42, 0.16);
      transition: transform 0.22s var(--ease-spring), background 0.2s ease, box-shadow 0.22s ease;
    }
    .nav-pill:hover {
      background: #000000;
      transform: translateY(-1px);
      box-shadow: 0 4px 12px rgba(15, 23, 42, 0.22);
    }

    /* === Sunlit Studio Hero Stage === */
    .hero {
      position: relative;
      padding: 50px 24px 72px;
      overflow: hidden;
      background:
        radial-gradient(ellipse 75% 48% at 50% 0%, rgba(0, 113, 227, 0.048), transparent 68%),
        radial-gradient(ellipse 90% 42% at 50% 100%, rgba(15, 23, 42, 0.03), transparent 72%),
        linear-gradient(180deg, #ffffff 0%, #fbfbfd 64%, #f4f5f8 100%);
    }
    #wafer-canvas {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      -webkit-mask-image: radial-gradient(ellipse 64% 44% at 50% 28%, rgba(0,0,0,0) 35%, rgba(0,0,0,1) 82%);
      mask-image: radial-gradient(ellipse 64% 44% at 50% 28%, rgba(0,0,0,0) 35%, rgba(0,0,0,1) 82%);
    }
    .hero-copy {
      position: relative;
      z-index: 2;
      max-width: 960px;
      margin: 0 auto;
      text-align: center;
    }
    .hero-kicker {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 5px 14px;
      border-radius: 980px;
      background: rgba(255, 255, 255, 0.85);
      border: 1px solid rgba(15, 23, 42, 0.085);
      box-shadow:
        0 1px 2px rgba(15, 23, 42, 0.04),
        0 4px 12px rgba(15, 23, 42, 0.04);
      font-size: 0.76rem;
      font-weight: 500;
      letter-spacing: -0.005em;
      color: var(--ink-2);
      margin-bottom: 18px;
    }
    .kicker-dot {
      width: 6.5px;
      height: 6.5px;
      border-radius: 50%;
      background: #169c63;
      box-shadow: 0 0 0 3px rgba(22, 156, 99, 0.16);
    }
    .hero h1 {
      margin: 0 auto 16px;
      font-size: clamp(2.45rem, 4.9vw, 4.35rem);
      font-weight: 600;
      line-height: 1.05;
      letter-spacing: -0.036em;
      color: var(--ink-1);
    }
    .hero h1 .muted-line {
      display: block;
      color: #86868b;
    }
    .hero-lead {
      max-width: 660px;
      margin: 0 auto 26px;
      font-size: clamp(1.02rem, 1.4vw, 1.17rem);
      line-height: 1.50;
      letter-spacing: -0.011em;
      color: var(--ink-2);
      font-weight: 400;
    }
    .hero-lead strong {
      color: var(--ink-1);
      font-weight: 600;
    }
    .hero-actions {
      display: flex;
      justify-content: center;
      flex-wrap: wrap;
      gap: 12px;
      margin-bottom: 42px;
    }
    .btn-primary {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 24px;
      border-radius: 980px;
      background: #1d1d1f;
      color: #ffffff;
      font-size: 0.91rem;
      font-weight: 600;
      letter-spacing: -0.012em;
      box-shadow:
        0 2px 4px rgba(15, 23, 42, 0.12),
        0 10px 22px -6px rgba(15, 23, 42, 0.24);
      transition: transform 0.26s var(--ease-spring), background 0.2s ease, box-shadow 0.26s ease;
    }
    .btn-primary:hover {
      background: #000000;
      transform: translateY(-2px);
      box-shadow:
        0 4px 10px rgba(15, 23, 42, 0.16),
        0 16px 32px -8px rgba(15, 23, 42, 0.30);
    }
    .btn-secondary {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 22px;
      border-radius: 980px;
      background: #ffffff;
      color: var(--ink-1);
      border: 1px solid rgba(15, 23, 42, 0.12);
      box-shadow:
        0 1px 2px rgba(15, 23, 42, 0.04),
        0 6px 16px -6px rgba(15, 23, 42, 0.08);
      font-size: 0.91rem;
      font-weight: 500;
      letter-spacing: -0.01em;
      transition: transform 0.26s var(--ease-spring), background 0.2s ease, border-color 0.2s ease, box-shadow 0.26s ease;
    }
    .btn-secondary:hover {
      background: #f8f9fb;
      border-color: rgba(15, 23, 42, 0.22);
      transform: translateY(-2px);
      box-shadow:
        0 3px 8px rgba(15, 23, 42, 0.06),
        0 12px 24px -8px rgba(15, 23, 42, 0.12);
    }

    /* === Tactile Gallery Plinth & 3D Hardcover Box-Set === */
    .hero-plinth-wrap {
      position: relative;
      z-index: 2;
      max-width: 1180px;
      margin: 0 auto;
    }
    /* Subtle architectural studio tabletop shelf surface under the books */
    .hero-plinth-wrap::after {
      content: "";
      position: absolute;
      left: 2%;
      right: 2%;
      bottom: 46px;
      height: 36px;
      border-radius: 50%;
      background: radial-gradient(ellipse at center, rgba(15, 23, 42, 0.075) 0%, transparent 72%);
      pointer-events: none;
      z-index: -1;
    }
    .hero-shelf {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 30px;
      perspective: 2200px;
      padding: 8px 14px 12px;
    }
    .shelf-book {
      position: relative;
      display: flex;
      flex-direction: column;
      align-items: center;
      outline: none;
      --fan: 1;
      --rx-tilt: 0deg;
      --ry-tilt: 0deg;
    }
    .book-3d {
      position: relative;
      width: 100%;
      max-width: 230px;
      aspect-ratio: 1400 / 1850;
      transform-style: preserve-3d;
      transform:
        translateY(calc(var(--base-ty, 0px) * var(--fan)))
        rotateY(calc(var(--base-ry, 0deg) * var(--fan) + var(--ry-tilt, 0deg)))
        rotateX(calc(3.5deg + var(--rx-tilt, 0deg)));
      transition: transform 0.55s var(--ease-spring);
      will-change: transform;
    }
    .shelf-book:hover .book-3d,
    .shelf-book:focus-visible .book-3d {
      transform:
        translate3d(0, -16px, 44px)
        rotateY(calc(-12deg + var(--ry-tilt, 0deg)))
        rotateX(calc(4deg + var(--rx-tilt, 0deg)));
    }
    .book-front {
      position: absolute;
      inset: 0;
      border-radius: 3px 7px 7px 3px;
      overflow: hidden;
      transform: translateZ(13px);
      background: #070b12;
      box-shadow:
        inset 0 0 0 0.5px rgba(255, 255, 255, 0.22),
        inset 0 1px 0 rgba(255, 255, 255, 0.28);
    }
    .book-front img {
      width: 100%;
      height: 100%;
      object-fit: cover;
      display: block;
    }
    /* Clothbound French-groove hinge crease along left spine */
    .book-crease {
      position: absolute;
      inset: 0;
      pointer-events: none;
      background: linear-gradient(
        90deg,
        rgba(255, 255, 255, 0.26) 0%,
        rgba(255, 255, 255, 0.06) 1.4%,
        rgba(0, 0, 0, 0.55) 3.0%,
        rgba(255, 255, 255, 0.14) 4.4%,
        rgba(0, 0, 0, 0.14) 5.8%,
        transparent 9.5%
      );
    }
    .book-sheen {
      position: absolute;
      inset: 0;
      pointer-events: none;
      opacity: 0;
      background: radial-gradient(
        circle 230px at var(--gx, 50%) var(--gy, 30%),
        rgba(255, 255, 255, 0.24),
        transparent 68%
      );
      transition: opacity 0.3s ease;
    }
    .tilt-stage:hover .book-sheen { opacity: 1; }

    /* Left 3D Hardcover Spine */
    .book-spine {
      position: absolute;
      top: 0;
      bottom: 0;
      left: -13px;
      width: 26px;
      background: linear-gradient(90deg, #060a12 0%, #131e30 52%, #080d17 100%);
      border-top: 0.5px solid rgba(255, 255, 255, 0.20);
      border-bottom: 0.5px solid rgba(0, 0, 0, 0.8);
      transform: rotateY(-90deg);
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: space-between;
      padding: 16px 0;
      overflow: hidden;
      backface-visibility: hidden;
    }
    .book-spine::before {
      content: "";
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: var(--vol-foil);
    }
    .spine-vol, .spine-title {
      writing-mode: vertical-rl;
      font-size: 7.5px;
      letter-spacing: 0.14em;
      font-weight: 600;
      color: rgba(245, 245, 247, 0.78);
      white-space: nowrap;
    }
    .spine-vol { color: var(--vol-foil); }

    /* Right 3D Archival Cream Paper Fore-Edge */
    .book-pages {
      position: absolute;
      top: 3px;
      bottom: 3px;
      right: -12px;
      width: 24px;
      transform: rotateY(90deg);
      background:
        linear-gradient(90deg, rgba(15,23,42,0.22), transparent 22%, rgba(15,23,42,0.16) 100%),
        repeating-linear-gradient(90deg, #f3f0e8 0px, #f3f0e8 1.5px, #dad5c9 1.5px, #dad5c9 2.5px);
      border-radius: 0 2px 2px 0;
      box-shadow: inset 0 0 0 0.5px rgba(15, 23, 42, 0.12);
    }
    /* Physical Multi-Layer Cast Shadow onto Daylight Surface */
    .book-back {
      position: absolute;
      inset: 0;
      border-radius: 3px 7px 7px 3px;
      background: #0a101b;
      transform: translateZ(-13px);
      box-shadow:
        -8px 12px 20px -4px rgba(15, 23, 42, 0.22),
        0 20px 38px -10px rgba(15, 23, 42, 0.30),
        0 38px 64px -16px rgba(15, 23, 42, 0.22);
      transition: box-shadow 0.55s var(--ease-spring);
    }
    .shelf-book:hover .book-back {
      box-shadow:
        -14px 24px 32px -6px rgba(15, 23, 42, 0.20),
        0 34px 58px -12px rgba(15, 23, 42, 0.28),
        0 52px 88px -18px rgba(var(--vol-rgb), 0.22);
    }
    /* Grounded Studio Contact Occlusion Shadow */
    .book-floor-shadow {
      width: 78%;
      height: 16px;
      margin-top: 20px;
      border-radius: 50%;
      background: radial-gradient(
        ellipse at center,
        rgba(15, 23, 42, 0.30) 0%,
        rgba(15, 23, 42, 0.11) 52%,
        transparent 76%
      );
      filter: blur(5px);
      transition: transform 0.55s var(--ease-spring), opacity 0.55s ease, background 0.45s ease;
    }
    .shelf-book:hover .book-floor-shadow {
      transform: scaleX(1.12) translateY(7px);
      opacity: 0.85;
      background: radial-gradient(
        ellipse at center,
        rgba(15, 23, 42, 0.24) 0%,
        rgba(var(--vol-rgb), 0.16) 48%,
        transparent 78%
      );
    }
    .shelf-caption {
      margin-top: 12px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 3px;
      text-align: center;
    }
    .shelf-vol-pill {
      font-size: 0.82rem;
      font-weight: 600;
      letter-spacing: -0.012em;
      color: var(--ink-1);
      transition: color 0.22s ease;
    }
    .shelf-book:hover .shelf-vol-pill { color: var(--vol-ink); }
    .shelf-metrics {
      font-family: var(--mono);
      font-size: 0.71rem;
      color: var(--ink-3);
    }

    /* === Section Scaffolding === */
    .section {
      position: relative;
      padding: 104px 24px;
      scroll-margin-top: 56px;
      border-top: 1px solid var(--hairline);
    }
    .section-grouped { background: var(--bg-grouped); }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    .section-header {
      max-width: 780px;
      margin-bottom: 56px;
    }
    .section-eyebrow {
      font-size: 0.79rem;
      font-weight: 600;
      letter-spacing: -0.005em;
      color: #0066cc;
      margin-bottom: 8px;
    }
    .section-title {
      margin: 0 0 14px;
      font-size: clamp(2rem, 4.2vw, 3.25rem);
      font-weight: 600;
      line-height: 1.08;
      letter-spacing: -0.032em;
      color: var(--ink-1);
    }
    .section-title span { color: #86868b; }
    .section-desc {
      margin: 0;
      font-size: clamp(1rem, 1.35vw, 1.14rem);
      line-height: 1.54;
      letter-spacing: -0.01em;
      color: var(--ink-2);
    }

    /* === Sculpted Daylight Cards === */
    .elevated-card {
      position: relative;
      background: var(--bg-card);
      border-radius: 28px;
      border: 1px solid var(--border-card);
      box-shadow: var(--shadow-card);
      overflow: hidden;
      transition: box-shadow 0.4s var(--ease-out-expo), transform 0.4s var(--ease-out-expo);
    }

    /* === Interactive 6-Tier Cross-OS Silicon-to-Cloud Visualizer === */
    .stack-explorer {
      padding: 32px;
      display: grid;
      grid-template-columns: 292px 1fr;
      gap: 36px;
      align-items: start;
    }
    .stack-rail {
      background: var(--bg-recessed);
      padding: 12px;
      border-radius: 22px;
      border: 1px solid rgba(15, 23, 42, 0.05);
      box-shadow: inset 0 1px 3px rgba(15, 23, 42, 0.04);
      display: flex;
      flex-direction: column;
      gap: 4px;
    }
    .rail-controls {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 6px;
      padding: 4px 8px;
    }
    .rail-title {
      font-family: var(--mono);
      font-size: 0.69rem;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--ink-3);
    }
    .autoplay-btn {
      background: #ffffff;
      border: 1px solid rgba(15, 23, 42, 0.10);
      color: var(--ink-2);
      border-radius: 980px;
      padding: 3px 11px;
      font-size: 0.70rem;
      font-weight: 600;
      box-shadow: 0 1px 2px rgba(15, 23, 42, 0.05);
      cursor: pointer;
      transition: background 0.2s ease, color 0.2s ease, transform 0.2s ease;
    }
    .autoplay-btn:hover { background: #ffffff; color: var(--ink-1); transform: scale(1.03); }

    .tier-btn {
      position: relative;
      width: 100%;
      text-align: left;
      padding: 12px 14px 13px;
      border-radius: 14px;
      border: 1px solid transparent;
      background: transparent;
      color: var(--ink-2);
      cursor: pointer;
      display: grid;
      grid-template-columns: 28px 1fr;
      align-items: center;
      gap: 6px;
      transition: background 0.24s ease, color 0.24s ease, box-shadow 0.24s ease;
    }
    .tier-btn:hover {
      color: var(--ink-1);
      background: rgba(255, 255, 255, 0.55);
    }
    .tier-btn.active {
      background: #ffffff;
      border-color: rgba(15, 23, 42, 0.065);
      color: var(--ink-1);
      box-shadow:
        0 1px 2px rgba(15, 23, 42, 0.05),
        0 6px 16px -4px rgba(15, 23, 42, 0.09);
    }
    .tier-num {
      font-family: var(--mono);
      font-size: 0.73rem;
      font-weight: 600;
      color: var(--ink-3);
    }
    .tier-btn.active .tier-num { color: #0066cc; }
    .tier-label {
      font-size: 0.87rem;
      font-weight: 600;
      letter-spacing: -0.012em;
    }
    .tier-progress {
      grid-column: 1 / -1;
      height: 2.5px;
      border-radius: 2px;
      background: rgba(15, 23, 42, 0.07);
      overflow: hidden;
      margin-top: 6px;
      opacity: 0;
      transition: opacity 0.2s ease;
    }
    .tier-btn.active .tier-progress { opacity: 1; }
    .tier-progress-fill {
      display: block;
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, #0066cc, #169c63);
      transition: width 0.1s linear;
    }

    .stack-stage {
      min-width: 0;
      padding: 6px 4px;
      transition: opacity 0.22s ease, transform 0.32s var(--ease-out-expo);
    }
    .stack-stage.switching {
      opacity: 0;
      transform: translateY(5px);
    }
    .stage-top {
      padding-bottom: 18px;
      margin-bottom: 18px;
      border-bottom: 1px solid var(--hairline);
    }
    .stage-top h3 {
      margin: 0 0 8px;
      font-size: 1.42rem;
      font-weight: 600;
      letter-spacing: -0.022em;
      color: var(--ink-1);
    }
    .stage-top p {
      margin: 0;
      font-size: 0.94rem;
      line-height: 1.52;
      color: var(--ink-2);
    }
    .signal-bus {
      width: 100%;
      height: 26px;
      margin-bottom: 16px;
      display: block;
    }
    .signal-pulse-line {
      stroke-dasharray: 96 420;
      animation: busFlow 3.2s linear infinite;
    }
    @keyframes busFlow {
      from { stroke-dashoffset: 516; }
      to { stroke-dashoffset: 0; }
    }
    @keyframes tileEnter {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    .os-compare-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }
    .os-tile {
      padding: 20px 22px;
      border-radius: 20px;
      background: #fbfbfd;
      border: 1px solid rgba(15, 23, 42, 0.075);
      box-shadow:
        0 1px 2px rgba(15, 23, 42, 0.025),
        0 6px 16px -8px rgba(15, 23, 42, 0.06);
      display: flex;
      flex-direction: column;
      gap: 11px;
      animation: tileEnter 0.38s var(--ease-out-expo) both;
      transition: transform 0.28s var(--ease-spring), border-color 0.25s ease, box-shadow 0.28s ease, background 0.25s ease;
    }
    .os-tile:nth-child(2) { animation-delay: 35ms; }
    .os-tile:nth-child(3) { animation-delay: 70ms; }
    .os-tile:nth-child(4) { animation-delay: 105ms; }
    .os-tile:hover {
      background: #ffffff;
      transform: translateY(-3px);
      border-color: rgba(var(--os-rgb), 0.38);
      box-shadow:
        0 4px 10px rgba(15, 23, 42, 0.04),
        0 16px 32px -10px rgba(15, 23, 42, 0.10);
    }
    .os-tile-head {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .os-badge {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      font-size: 0.86rem;
      font-weight: 600;
      color: var(--ink-1);
    }
    .os-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--os-dot);
      box-shadow: 0 0 0 3px rgba(var(--os-rgb), 0.15);
    }
    .os-jump {
      font-size: 0.74rem;
      font-weight: 600;
      color: var(--ink-3);
      transition: color 0.2s ease, transform 0.2s ease;
    }
    .os-tile:hover .os-jump { color: var(--os-ink); transform: translateX(2px); }
    .os-prims {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .prim-chip {
      font-family: var(--mono);
      font-size: 0.70rem;
      font-weight: 500;
      padding: 3px 8px;
      border-radius: 6px;
      background: rgba(var(--os-rgb), 0.075);
      border: 1px solid rgba(var(--os-rgb), 0.20);
      color: var(--os-ink);
    }
    .os-row-label {
      font-family: var(--mono);
      font-size: 0.64rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--ink-3);
      display: block;
      margin-bottom: 3px;
    }
    .os-inv, .os-break {
      margin: 0;
      font-size: 0.82rem;
      line-height: 1.48;
      color: var(--ink-1);
    }
    .os-break { color: var(--ink-2); }

    /* === Editorial Volume Showcases (#volumes) === */
    .volumes-stack {
      display: flex;
      flex-direction: column;
      gap: 34px;
    }
    .vol-showcase {
      padding: 24px;
      display: grid;
      grid-template-columns: 340px 1fr;
      gap: 44px;
      align-items: center;
    }
    .vol-showcase:hover {
      box-shadow: var(--shadow-card-hover);
    }
    /* Recessed Studio Photography Alcove Framing the Dark Hardcover Book */
    .vol-visual-alcove {
      background: var(--alcove-bg);
      border-radius: 20px;
      border: 1px solid rgba(15, 23, 42, 0.055);
      box-shadow: inset 0 2px 6px rgba(15, 23, 42, 0.035);
      padding: 40px 28px 34px;
      display: flex;
      justify-content: center;
      perspective: 1800px;
      --rx-tilt: 0deg;
      --ry-tilt: 0deg;
    }
    .showcase-book-stage {
      display: flex;
      flex-direction: column;
      align-items: center;
      width: 212px;
    }
    .showcase-3d {
      max-width: 212px;
      transform:
        rotateY(calc(-15deg + var(--ry-tilt, 0deg)))
        rotateX(calc(4deg + var(--rx-tilt, 0deg)));
      transition: transform 0.6s var(--ease-spring);
    }
    .vol-showcase:hover .showcase-3d {
      transform:
        translate3d(0, -10px, 26px)
        rotateY(calc(-8deg + var(--ry-tilt, 0deg)))
        rotateX(calc(2.5deg + var(--rx-tilt, 0deg)));
    }
    .showcase-shadow {
      margin-top: 24px;
      background: radial-gradient(
        ellipse at center,
        rgba(15, 23, 42, 0.32) 0%,
        rgba(15, 23, 42, 0.12) 52%,
        transparent 78%
      );
    }
    .vol-copy-col {
      padding: 18px 24px 18px 0;
    }
    .vol-eyebrow {
      font-size: 0.78rem;
      font-weight: 600;
      letter-spacing: -0.005em;
      color: var(--vol-ink);
      margin-bottom: 8px;
    }
    .vol-title {
      margin: 0 0 8px;
      font-size: clamp(1.75rem, 3vw, 2.4rem);
      font-weight: 600;
      letter-spacing: -0.03em;
      line-height: 1.1;
      color: var(--ink-1);
    }
    .vol-subheadline {
      margin: 0 0 12px;
      font-size: 1.10rem;
      font-weight: 500;
      letter-spacing: -0.015em;
      color: #3a3a3c;
    }
    .vol-blurb {
      margin: 0 0 20px;
      font-size: 0.94rem;
      line-height: 1.58;
      color: var(--ink-2);
    }
    .spec-parts-list {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px 18px;
      margin-bottom: 24px;
    }
    .spec-part-item {
      display: flex;
      align-items: baseline;
      gap: 8px;
      font-size: 0.80rem;
      line-height: 1.42;
      color: #3a3a3c;
    }
    .spec-dot {
      flex-shrink: 0;
      width: 5.5px;
      height: 5.5px;
      border-radius: 50%;
      background: var(--vol-dot);
      transform: translateY(-1px);
    }
    .vol-stat-strip {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      padding: 15px 0;
      margin-bottom: 24px;
      border-top: 1px solid var(--hairline);
      border-bottom: 1px solid var(--hairline);
    }
    .vol-stat-strip strong {
      display: block;
      font-size: 1.35rem;
      font-weight: 600;
      letter-spacing: -0.025em;
      color: var(--ink-1);
    }
    .vol-stat-strip span {
      font-size: 0.73rem;
      color: var(--ink-3);
    }
    .vol-actions {
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
    }

    /* === Craft & Verification Bento Grid (#craft) === */
    .bento-grid {
      display: grid;
      grid-template-columns: repeat(12, minmax(0, 1fr));
      gap: 20px;
    }
    .bento-tile {
      padding: 34px 36px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      gap: 18px;
    }
    .bento-tile:hover {
      transform: translateY(-3px);
      box-shadow: var(--shadow-card-hover);
    }
    .span-7 { grid-column: span 7; }
    .span-5 { grid-column: span 5; }
    .span-4 { grid-column: span 4; }
    .bento-metric {
      font-size: clamp(2.6rem, 4.8vw, 3.9rem);
      font-weight: 600;
      letter-spacing: -0.04em;
      line-height: 1;
      color: var(--ink-1);
    }
    .bento-tile h3 {
      margin: 0 0 8px;
      font-size: 1.22rem;
      font-weight: 600;
      letter-spacing: -0.02em;
      color: var(--ink-1);
    }
    .bento-tile p {
      margin: 0;
      font-size: 0.91rem;
      line-height: 1.54;
      color: var(--ink-2);
    }
    .bento-diagram {
      width: 100%;
      height: auto;
      border-radius: 16px;
      background: #f8fafc;
      border: 1px solid rgba(15, 23, 42, 0.08);
      box-shadow: inset 0 1px 2px rgba(15, 23, 42, 0.03);
      padding: 14px;
    }
    .ortho-trace {
      stroke-dasharray: 8 6;
      animation: orthoMove 5.5s linear infinite;
    }
    @keyframes orthoMove {
      to { stroke-dashoffset: -84; }
    }

    /* === Scroll Reveal Choreography === */
    .reveal {
      opacity: 0;
      transform: translateY(22px);
      transition: opacity 0.75s var(--ease-out-expo), transform 0.75s var(--ease-out-expo);
    }
    .reveal.in-view {
      opacity: 1;
      transform: translateY(0);
    }

    /* === Daylight Apple-Style Footer === */
    .site-footer {
      border-top: 1px solid var(--hairline);
      background: #f5f5f7;
      padding: 60px 24px 44px;
      color: var(--ink-3);
      font-size: 0.80rem;
    }
    .footer-grid {
      max-width: 1200px;
      margin: 0 auto 40px;
      display: grid;
      grid-template-columns: 2fr 1fr 1fr 1fr;
      gap: 36px;
    }
    .footer-brand p {
      max-width: 340px;
      margin: 12px 0 0;
      line-height: 1.55;
      color: var(--ink-2);
    }
    .footer-col h4 {
      margin: 0 0 12px;
      font-size: 0.76rem;
      font-weight: 600;
      color: var(--ink-1);
      letter-spacing: -0.005em;
    }
    .footer-col ul {
      list-style: none;
      margin: 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: 9px;
    }
    .footer-col a {
      color: var(--ink-2);
      transition: color 0.2s ease;
    }
    .footer-col a:hover { color: var(--ink-1); }
    .footer-bottom {
      max-width: 1200px;
      margin: 0 auto;
      padding-top: 22px;
      border-top: 1px solid var(--hairline);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    /* === Responsive Breakpoints === */
    @media (max-width: 1024px) {
      .hero-shelf {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        max-width: 580px;
        margin: 0 auto;
        gap: 36px 28px;
      }
      .stack-explorer { grid-template-columns: 1fr; padding: 22px; }
      .stack-rail {
        flex-direction: row;
        overflow-x: auto;
        padding: 8px;
      }
      .rail-controls { display: none; }
      .tier-btn { min-width: 188px; }
      .vol-showcase {
        grid-template-columns: 1fr;
        padding: 22px;
        gap: 28px;
      }
      .vol-copy-col { padding: 4px 8px 10px; }
      .span-7, .span-5, .span-4 { grid-column: span 12; }
      .footer-grid { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 640px) {
      .nav-links, .nav-gh { display: none; }
      .hero { padding: 38px 18px 54px; }
      .hero-shelf { gap: 28px 16px; }
      .os-compare-grid, .spec-parts-list { grid-template-columns: 1fr; }
      .vol-stat-strip { grid-template-columns: repeat(2, 1fr); }
      .footer-grid { grid-template-columns: 1fr; }
    }
    @media (prefers-reduced-motion: reduce) {
      *, *::before, *::after {
        animation-duration: 0.01ms !important;
        animation-iteration-count: 1 !important;
        transition-duration: 0.01ms !important;
        scroll-behavior: auto !important;
      }
      .reveal { opacity: 1 !important; transform: none !important; }
    }
  </style>
</head>
<body>
  <nav class="local-nav" id="local-nav" aria-label="Series Navigation">
    <div class="local-nav-inner">
      <a class="brand-lockup" href="#top">
        <span class="brand-die" aria-hidden="true"></span>
        <span>Platform Trust Chain</span>
      </a>
      <div class="nav-links">
        <a href="#stack">Interactive Chain</a>
        <a href="#volumes">The Four Volumes</a>
        <a href="#craft">Verification &amp; Craft</a>
      </div>
      <div class="nav-cta-group">
        <a class="nav-gh" href="${esc(registry.repoUrl)}">GitHub</a>
        <a class="nav-pill" href="#volumes">Read Free</a>
      </div>
    </div>
  </nav>

  <header class="hero" id="top">
    <canvas id="wafer-canvas" aria-hidden="true"></canvas>
    <div class="hero-copy">
      <div class="hero-kicker">
        <span class="kicker-dot" aria-hidden="true"></span>
        <span>Four Complete Monographs &middot; 1,457 Print Pages &middot; Open Access</span>
      </div>
      <h1>
        Four operating systems.
        <span class="muted-line">Traced from silicon reset to cloud.</span>
      </h1>
      <p class="hero-lead">
        An engineering monograph series by <strong>${esc(registry.author)}</strong> dissecting how
        <strong>Windows</strong>, <strong>Apple</strong>, <strong>Linux</strong>, and <strong>Android</strong>
        construct cryptographic chains of trust across hardware, hypervisors, kernels, credentials, and confidential AI, and the exact seams where real attackers break them.
      </p>
      <div class="hero-actions">
        <a class="btn-primary" href="#volumes">
          <span>Explore the Four Volumes</span>
          <svg width="15" height="15" viewBox="0 0 16 16" fill="none" aria-hidden="true"><path d="M8 3.5v9M4 8.5l4 4 4-4" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/></svg>
        </a>
        <a class="btn-secondary" href="#stack">Compare Trust Chains</a>
      </div>
    </div>

    <div class="hero-plinth-wrap">
      <div class="hero-shelf" id="hero-shelf">
        ${heroBooksHtml}
      </div>
    </div>
  </header>

  <section class="section section-grouped" id="stack">
    <div class="container">
      <div class="section-header reveal">
        <div class="section-eyebrow">Cross-Platform Architecture</div>
        <h2 class="section-title">Six links in the chain. <span>Four radically different bets.</span></h2>
        <p class="section-desc">
          Step through each hardware and software boundary from power-on reset to confidential AI enclaves to inspect how every platform enforces its invariant and where in-the-wild exploit chains break through.
        </p>
      </div>

      <div class="stack-explorer elevated-card reveal">
        <div class="stack-rail" role="tablist" aria-label="Trust chain layers">
          <div class="rail-controls">
            <span class="rail-title">Select Layer</span>
            <button class="autoplay-btn" id="autoplay-toggle" type="button" aria-pressed="true">Pause</button>
          </div>
          ${stackButtonsHtml}
        </div>

        <div class="stack-stage" id="stack-stage" role="tabpanel" aria-live="polite">
          <div class="stage-top">
            <h3 id="stage-title"></h3>
            <p id="stage-summary"></p>
          </div>
          <svg class="signal-bus" viewBox="0 0 800 26" fill="none" aria-hidden="true">
            <line x1="8" y1="13" x2="792" y2="13" stroke="rgba(15,23,42,0.10)" stroke-width="1.4"/>
            <line class="signal-pulse-line" x1="8" y1="13" x2="792" y2="13" stroke="url(#busGrad)" stroke-width="2.2"/>
            <circle cx="100" cy="13" r="4" fill="#c88a12"/>
            <circle cx="300" cy="13" r="4" fill="#0071e3"/>
            <circle cx="500" cy="13" r="4" fill="#d96518"/>
            <circle cx="700" cy="13" r="4" fill="#169c63"/>
            <defs>
              <linearGradient id="busGrad" x1="0" y1="0" x2="800" y2="0" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#c88a12" stop-opacity="0"/>
                <stop offset="35%" stop-color="#0071e3"/>
                <stop offset="70%" stop-color="#169c63"/>
                <stop offset="100%" stop-color="#169c63" stop-opacity="0"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="os-compare-grid" id="os-compare-grid"></div>
        </div>
      </div>
    </div>
  </section>

  <section class="section" id="volumes">
    <div class="container">
      <div class="section-header reveal">
        <div class="section-eyebrow">The Complete Box Set</div>
        <h2 class="section-title">Built for practitioners. <span>Read online or in print-ready PDF.</span></h2>
        <p class="section-desc">
          Every volume stands alone as a deep architectural reference with full-bleed vector covers, hyperlinked tables of contents, sustained book prose, and reproducible live-system verification commands.
        </p>
      </div>

      <div class="volumes-stack">
        ${volumeCardsHtml}
      </div>
    </div>
  </section>

  <section class="section section-grouped" id="craft">
    <div class="container">
      <div class="section-header reveal">
        <div class="section-eyebrow">Precision Engineering</div>
        <h2 class="section-title">Mechanically verified. <span>Down to every pixel and citation.</span></h2>
        <p class="section-desc">
          Technical books rot when diagrams drift, links break, or prose dissolves into slide bullets. All four monographs are compiled and audited by a deterministic build suite on every commit.
        </p>
      </div>

      <div class="bento-grid">
        <div class="bento-tile elevated-card span-7 reveal">
          <div>
            <div class="section-eyebrow">Collision-Verified Schematics</div>
            <h3>266 programmatic vector diagrams</h3>
            <p>
              Every architecture schematic is authored in Python atop a custom layout engine enforcing strict orthogonal routing, row-synchronized split domains, masked edge labels, and automated seven-way collision assertions.
            </p>
          </div>
          <svg class="bento-diagram" viewBox="0 0 620 128" fill="none" aria-hidden="true">
            <rect x="16" y="26" width="148" height="76" rx="10" fill="#eef4fb" stroke="#0071e3" stroke-opacity="0.38" stroke-width="1.3"/>
            <text x="90" y="56" fill="#1d1d1f" font-size="11" font-weight="600" text-anchor="middle" font-family="ui-monospace, monospace">SILICON ROOT</text>
            <text x="90" y="76" fill="#515154" font-size="9.5" text-anchor="middle" font-family="ui-monospace, monospace">UID / ECID / VCEK</text>

            <rect x="236" y="26" width="148" height="76" rx="10" fill="#fbf5e8" stroke="#c88a12" stroke-opacity="0.42" stroke-width="1.3"/>
            <text x="310" y="56" fill="#1d1d1f" font-size="11" font-weight="600" text-anchor="middle" font-family="ui-monospace, monospace">EL2 / VTL1 / SPTM</text>
            <text x="310" y="76" fill="#515154" font-size="9.5" text-anchor="middle" font-family="ui-monospace, monospace">Stage-2 Page Lock</text>

            <rect x="456" y="26" width="148" height="76" rx="10" fill="#ebf6f0" stroke="#169c63" stroke-opacity="0.42" stroke-width="1.3"/>
            <text x="530" y="56" fill="#1d1d1f" font-size="11" font-weight="600" text-anchor="middle" font-family="ui-monospace, monospace">ATTESTED TEE</text>
            <text x="530" y="76" fill="#515154" font-size="9.5" text-anchor="middle" font-family="ui-monospace, monospace">PCC / SVSM / TIE</text>

            <line x1="164" y1="64" x2="236" y2="64" stroke="rgba(15,23,42,0.14)" stroke-width="1.5"/>
            <line class="ortho-trace" x1="164" y1="64" x2="236" y2="64" stroke="#0071e3" stroke-width="2"/>
            <line x1="384" y1="64" x2="456" y2="64" stroke="rgba(15,23,42,0.14)" stroke-width="1.5"/>
            <line class="ortho-trace" x1="384" y1="64" x2="456" y2="64" stroke="#169c63" stroke-width="2"/>
          </svg>
        </div>

        <div class="bento-tile elevated-card span-5 reveal">
          <div class="bento-metric" data-target="2587" data-suffix="">2,587</div>
          <div>
            <h3>Primary-source citations</h3>
            <p>
              Anchored directly to normative specifications, RFCs, TCG/UEFI/ARM manuals, XNU/Linux/AOSP source trees, and primary CVE advisories, audited for zero unresolved links or uncited orphans.
            </p>
          </div>
        </div>

        <div class="bento-tile elevated-card span-4 reveal">
          <div class="bento-metric" data-target="1457" data-suffix="">1,457</div>
          <div>
            <h3>Print-ready 7 &times; 9.25 in pages</h3>
            <p>
              Typeset in Georgia with KaTeX mathematical notation, proportional overflow-free tables, native PDF outlines, and full-bleed vector covers.
            </p>
          </div>
        </div>

        <div class="bento-tile elevated-card span-4 reveal">
          <div class="bento-metric" data-target="404" data-suffix="K">404K</div>
          <div>
            <h3>Sustained monograph words</h3>
            <p>
              Written in continuous architectural prose rather than slide-deck bullets, separating local primitive validity from end-to-end system authorization.
            </p>
          </div>
        </div>

        <div class="bento-tile elevated-card span-4 reveal">
          <div class="bento-metric" data-target="83" data-suffix="">83</div>
          <div>
            <h3>Chapters across four stacks</h3>
            <p>
              Updated through 2026 silicon and cloud milestones including A19/M5 EMTE, systemd run0, Android 17 Intrusion Logging, and MCP agent isolation.
            </p>
          </div>
        </div>
      </div>
    </div>
  </section>

  <footer class="site-footer">
    <div class="footer-grid">
      <div class="footer-brand">
        <div class="brand-lockup">
          <span class="brand-die" aria-hidden="true"></span>
          <span>${esc(registry.seriesTitle)}</span>
        </div>
        <p>
          Open technical security monographs by <a href="https://paragmali.com" style="color:#1d1d1f;font-weight:500;text-decoration:underline;text-underline-offset:3px;">${esc(registry.author)}</a>. Free to read online and download for personal and educational study under CC BY-NC-SA 4.0.
        </p>
      </div>
      <div class="footer-col">
        <h4>Web Editions</h4>
        <ul>
          <li><a href="${rootRel}windows/index.html">Vol. I &middot; Windows</a></li>
          <li><a href="${rootRel}apple/index.html">Vol. II &middot; Apple</a></li>
          <li><a href="${rootRel}linux/index.html">Vol. III &middot; Linux</a></li>
          <li><a href="${rootRel}android/index.html">Vol. IV &middot; Android</a></li>
        </ul>
      </div>
      <div class="footer-col">
        <h4>PDF Editions</h4>
        <ul>
          <li><a href="${rootRel}windows/the-windows-trust-chain.pdf" data-vol="windows">Windows PDF (379 pp)</a></li>
          <li><a href="${rootRel}apple/the-apple-trust-chain.pdf" data-vol="apple">Apple PDF (357 pp)</a></li>
          <li><a href="${rootRel}linux/the-linux-trust-chain.pdf" data-vol="linux">Linux PDF (363 pp)</a></li>
          <li><a href="${rootRel}android/the-android-trust-chain.pdf" data-vol="android">Android PDF (358 pp)</a></li>
        </ul>
      </div>
      <div class="footer-col">
        <h4>Repository</h4>
        <ul>
          <li><a href="${esc(registry.repoUrl)}">GitHub Monorepo</a></li>
          <li><a href="${esc(registry.repoUrl)}/blob/main/editorial.md">Editorial Playbook</a></li>
          <li><a href="${esc(registry.repoUrl)}/issues">Report an Issue</a></li>
          <li><a href="https://paragmali.com">paragmali.com</a></li>
        </ul>
      </div>
    </div>
    <div class="footer-bottom">
      <span>Copyright &copy; 2026 ${esc(registry.author)}. Licensed under CC BY-NC-SA 4.0. Commercial rights reserved.</span>
      <span>Built with mdBook, KaTeX, and programmatic SVG schematics.</span>
    </div>
  </footer>

  <script>
  (function () {
    var LAYERS = ${stackDataJson};
    var OS_META = [
      { key: 'windows', name: 'Vol. I · Windows', ink: '#946200', dot: '#c88a12', rgb: '180, 122, 14' },
      { key: 'apple',   name: 'Vol. II · Apple',  ink: '#0066cc', dot: '#0071e3', rgb: '0, 113, 227' },
      { key: 'linux',   name: 'Vol. III · Linux', ink: '#b34d00', dot: '#d96518', rgb: '217, 101, 24' },
      { key: 'android', name: 'Vol. IV · Android',ink: '#0b7a4b', dot: '#169c63', rgb: '22, 156, 99' }
    ];
    var reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function escHtml(s) {
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // Sticky nav shadow on scroll
    var navEl = document.getElementById('local-nav');
    window.addEventListener('scroll', function () {
      if (navEl) navEl.classList.toggle('scrolled', window.scrollY > 10);
    }, { passive: true });

    // 1. Interactive 6-Tier Stack Explorer + Auto-Cycle Progress
    var stage = document.getElementById('stack-stage');
    var titleEl = document.getElementById('stage-title');
    var sumEl = document.getElementById('stage-summary');
    var gridEl = document.getElementById('os-compare-grid');
    var btns = Array.prototype.slice.call(document.querySelectorAll('.tier-btn'));
    var toggleBtn = document.getElementById('autoplay-toggle');
    var activeIdx = 0;
    var playing = !reducedMotion;
    var DURATION = 6800;
    var lastTick = performance.now();
    var elapsed = 0;

    function renderTier(idx, animate) {
      activeIdx = idx;
      elapsed = 0;
      btns.forEach(function (b, i) {
        var on = i === idx;
        b.classList.toggle('active', on);
        b.setAttribute('aria-selected', on ? 'true' : 'false');
        var fill = b.querySelector('.tier-progress-fill');
        if (fill) fill.style.width = on && !playing ? '100%' : '0%';
      });

      function updateDom() {
        var layer = LAYERS[idx];
        titleEl.textContent = layer.num + ' · ' + layer.title;
        sumEl.textContent = layer.summary;
        gridEl.innerHTML = OS_META.map(function (m) {
          var d = layer.os[m.key];
          var chips = d.prims.map(function (p) {
            return '<span class="prim-chip">' + escHtml(p) + '</span>';
          }).join('');
          return (
            '<a class="os-tile" href="' + escHtml(layer.links[m.key]) + '" style="--os-ink:' + m.ink + '; --os-dot:' + m.dot + '; --os-rgb:' + m.rgb + ';">' +
              '<div class="os-tile-head">' +
                '<span class="os-badge"><span class="os-dot"></span>' + escHtml(m.name) + '</span>' +
                '<span class="os-jump">Open Volume &rarr;</span>' +
              '</div>' +
              '<div class="os-prims">' + chips + '</div>' +
              '<div><span class="os-row-label">Enforced Invariant</span><p class="os-inv">' + escHtml(d.invariant) + '</p></div>' +
              '<div><span class="os-row-label">Where Attackers Break It</span><p class="os-break">' + escHtml(d.breakCase) + '</p></div>' +
            '</a>'
          );
        }).join('');
      }

      if (animate && !reducedMotion) {
        stage.classList.add('switching');
        setTimeout(function () {
          updateDom();
          stage.classList.remove('switching');
        }, 160);
      } else {
        updateDom();
      }
    }

    btns.forEach(function (b) {
      b.addEventListener('click', function () {
        playing = false;
        if (toggleBtn) { toggleBtn.textContent = 'Play'; toggleBtn.setAttribute('aria-pressed', 'false'); }
        renderTier(Number(b.getAttribute('data-tier')), true);
      });
    });

    if (toggleBtn) {
      if (!playing) { toggleBtn.textContent = 'Play'; toggleBtn.setAttribute('aria-pressed', 'false'); }
      toggleBtn.addEventListener('click', function () {
        playing = !playing;
        toggleBtn.textContent = playing ? 'Pause' : 'Play';
        toggleBtn.setAttribute('aria-pressed', playing ? 'true' : 'false');
        lastTick = performance.now();
      });
    }

    renderTier(0, false);

    function stepCycle(now) {
      var dt = now - lastTick;
      lastTick = now;
      if (playing) {
        elapsed += dt;
        var pct = Math.min(100, (elapsed / DURATION) * 100);
        var activeFill = btns[activeIdx] && btns[activeIdx].querySelector('.tier-progress-fill');
        if (activeFill) activeFill.style.width = pct + '%';
        if (elapsed >= DURATION) {
          renderTier((activeIdx + 1) % LAYERS.length, true);
        }
      }
      requestAnimationFrame(stepCycle);
    }
    if (!reducedMotion) requestAnimationFrame(stepCycle);

    // 2. Interactive 3D Tilt + Cursor-Tracked Specular Gloss on Books
    if (!reducedMotion) {
      document.querySelectorAll('.tilt-stage').forEach(function (stageEl) {
        var front = stageEl.querySelector('.book-front');
        stageEl.addEventListener('pointermove', function (e) {
          var r = stageEl.getBoundingClientRect();
          var nx = (e.clientX - r.left) / r.width;
          var ny = (e.clientY - r.top) / r.height;
          stageEl.style.setProperty('--ry-tilt', ((nx - 0.5) * 9).toFixed(2) + 'deg');
          stageEl.style.setProperty('--rx-tilt', ((0.5 - ny) * 6).toFixed(2) + 'deg');
          if (front) {
            front.style.setProperty('--gx', (nx * 100).toFixed(1) + '%');
            front.style.setProperty('--gy', (ny * 100).toFixed(1) + '%');
          }
        });
        stageEl.addEventListener('pointerleave', function () {
          stageEl.style.setProperty('--ry-tilt', '0deg');
          stageEl.style.setProperty('--rx-tilt', '0deg');
        });
      });
    }

    // 3. Scroll-Linked Shelf Fan Choreography & Reveal + Count-Up Observer
    var shelfBooks = Array.prototype.slice.call(document.querySelectorAll('.shelf-book'));
    if (!reducedMotion && shelfBooks.length) {
      window.addEventListener('scroll', function () {
        var y = Math.min(1, Math.max(0, window.scrollY / 420));
        var fan = (1 - y * 0.45).toFixed(3);
        shelfBooks.forEach(function (sb) { sb.style.setProperty('--fan', fan); });
      }, { passive: true });
    }

    function animateMetric(el) {
      var target = Number(el.getAttribute('data-target'));
      var suffix = el.getAttribute('data-suffix') || '';
      if (!target || reducedMotion) return;
      var start = Math.floor(target * 0.82);
      var t0 = performance.now();
      var dur = 900;
      function tick(now) {
        var p = Math.min(1, (now - t0) / dur);
        var eased = 1 - Math.pow(1 - p, 3);
        var val = Math.round(start + (target - start) * eased);
        el.textContent = val.toLocaleString('en-US') + suffix;
        if (p < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }

    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (en.isIntersecting) {
            en.target.classList.add('in-view');
            en.target.querySelectorAll('[data-target]').forEach(animateMetric);
            io.unobserve(en.target);
          }
        });
      }, { threshold: 0.12 });
      document.querySelectorAll('.reveal').forEach(function (el) { io.observe(el); });
    } else {
      document.querySelectorAll('.reveal').forEach(function (el) { el.classList.add('in-view'); });
    }

    // 4. Subtle Daylight Architectural Wafer-Schematic Canvas in Hero
    var canvas = document.getElementById('wafer-canvas');
    if (canvas && canvas.getContext && !reducedMotion) {
      var ctx = canvas.getContext('2d');
      var cw = 0, ch = 0, dpr = Math.min(2, window.devicePixelRatio || 1);
      var colors = ['#c88a12', '#0071e3', '#d96518', '#169c63'];
      var traces = [];

      function resize() {
        var rect = canvas.parentElement.getBoundingClientRect();
        cw = rect.width;
        ch = rect.height;
        canvas.width = cw * dpr;
        canvas.height = ch * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        traces = [];
        var cols = Math.max(8, Math.floor(cw / 128));
        for (var i = 0; i < cols; i++) {
          var x = ((i + 0.5) / cols) * cw;
          traces.push({
            x: x,
            jog: (i % 2 === 0 ? 1 : -1) * 26,
            jogY: ch * (0.30 + (i % 3) * 0.15),
            pos: Math.random() * ch,
            speed: 0.42 + (i % 4) * 0.16,
            col: colors[i % colors.length]
          });
        }
      }
      resize();
      window.addEventListener('resize', resize);

      var heroVisible = true;
      if ('IntersectionObserver' in window) {
        new IntersectionObserver(function (e) { heroVisible = e[0].isIntersecting; }).observe(canvas);
      }

      function draw() {
        if (heroVisible) {
          ctx.clearRect(0, 0, cw, ch);
          ctx.lineWidth = 1;
          for (var i = 0; i < traces.length; i++) {
            var t = traces[i];
            ctx.strokeStyle = 'rgba(15, 23, 42, 0.045)';
            ctx.beginPath();
            ctx.moveTo(t.x, ch);
            ctx.lineTo(t.x, t.jogY + 24);
            ctx.lineTo(t.x + t.jog, t.jogY);
            ctx.lineTo(t.x + t.jog, 0);
            ctx.stroke();

            t.pos -= t.speed;
            if (t.pos < -60) t.pos = ch + 50;
            var py = t.pos;
            var px = py > t.jogY + 24 ? t.x : (py < t.jogY ? t.x + t.jog : t.x + t.jog * (1 - (py - t.jogY) / 24));
            var grad = ctx.createRadialGradient(px, py, 0, px, py, 16);
            grad.addColorStop(0, t.col + '2e');
            grad.addColorStop(1, t.col + '00');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(px, py, 16, 0, Math.PI * 2);
            ctx.fill();

            ctx.fillStyle = t.col;
            ctx.beginPath();
            ctx.arc(px, py, 1.8, 0, Math.PI * 2);
            ctx.fill();
          }
        }
        requestAnimationFrame(draw);
      }
      requestAnimationFrame(draw);
    }
  })();
  </script>
</body>
</html>\n`;
}

export function writeSeriesPortals(bookDir, registry) {
  writeFileSync(path.join(bookDir, 'index.html'), renderSeriesPortalHtml(registry, ''), 'utf8');
  const seriesDir = path.join(bookDir, 'series');
  mkdirSync(seriesDir, { recursive: true });
  writeFileSync(path.join(seriesDir, 'index.html'), renderSeriesPortalHtml(registry, '../'), 'utf8');
}
