#!/usr/bin/env node
/**
 * Generates the flagship Apple-product-page-grade interactive Series Showcase
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
    rgb: '212, 168, 67',
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
    rgb: '124, 196, 248',
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
    rgb: '229, 149, 75',
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
    rgb: '87, 201, 140',
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

  // Hero 3D shelf items
  const shelfAngles = [-10.5, -3.5, 3.5, 10.5];
  const shelfY = [18, 4, 4, 18];
  const heroBooksHtml = registry.volumes
    .map((v, idx) => {
      const meta = VOLUME_SHOWCASE[v.slug];
      const bookHref = `${rootRel}${v.mount}/index.html`;
      const coverSrc = `${rootRel}${v.mount}/cover.png`;
      return `
        <a class="shelf-book" href="${bookHref}" data-idx="${idx}"
           style="--base-ry:${shelfAngles[idx]}deg; --base-ty:${shelfY[idx]}px; --vol-rgb:${meta.rgb}; --vol-hex:${v.accent};"
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
            <span class="shelf-vol-pill">${esc(v.volume)} · ${esc(v.shortName)}</span>
            <span class="shelf-metrics">${v.chapters} Ch · ${v.pages} pp</span>
          </div>
        </a>`;
    })
    .join('\n');

  // Detailed 2-up volume showcases
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
        <article class="vol-showcase spotlight-card reveal" style="--vol-rgb:${meta.rgb}; --vol-hex:${v.accent};">
          <div class="vol-visual-col">
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
              <a class="btn-glass" href="${pdfHref}" data-vol="${v.slug}">
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
  <meta name="theme-color" content="#000000">
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
      color-scheme: dark;
      --bg-pure: #000000;
      --bg-elevated: #0b0b0e;
      --bg-card: #121216;
      --bg-card-hover: #17171c;
      --ink-1: #f5f5f7;
      --ink-2: #a1a1a6;
      --ink-3: #6e6e73;
      --hairline: rgba(255, 255, 255, 0.085);
      --specular: rgba(255, 255, 255, 0.14);
      --ease-out-expo: cubic-bezier(0.16, 1, 0.3, 1);
      --ease-spring: cubic-bezier(0.22, 1, 0.36, 1);
      --sans: -apple-system, BlinkMacSystemFont, "SF Pro Display", "SF Pro Text", "Helvetica Neue", Inter, system-ui, sans-serif;
      --mono: ui-monospace, "SF Mono", "JetBrains Mono", Menlo, Consolas, monospace;
      --shadow-ambient:
        0 2px 4px rgba(0, 0, 0, 0.45),
        0 12px 28px -6px rgba(0, 0, 0, 0.65),
        0 36px 72px -16px rgba(0, 0, 0, 0.82);
    }

    *, *::before, *::after { box-sizing: border-box; }
    html {
      scroll-behavior: smooth;
      background: var(--bg-pure);
      color: var(--ink-1);
      font-family: var(--sans);
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
      text-rendering: optimizeLegibility;
    }
    body {
      margin: 0;
      background: var(--bg-pure);
      overflow-x: hidden;
    }
    a { color: inherit; text-decoration: none; }
    button { font-family: inherit; }

    /* === Sticky Frosted-Glass Apple Local Nav === */
    .local-nav {
      position: sticky;
      top: 0;
      z-index: 100;
      height: 52px;
      background: rgba(8, 8, 10, 0.74);
      backdrop-filter: saturate(180%) blur(22px);
      -webkit-backdrop-filter: saturate(180%) blur(22px);
      border-bottom: 0.5px solid rgba(255, 255, 255, 0.11);
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
      font-size: 0.90rem;
      font-weight: 600;
      letter-spacing: -0.015em;
      color: var(--ink-1);
    }
    .brand-die {
      width: 20px;
      height: 20px;
      border-radius: 5px;
      background: linear-gradient(145deg, rgba(255,255,255,0.18), rgba(255,255,255,0.04));
      border: 0.5px solid rgba(255,255,255,0.28);
      display: grid;
      place-items: center;
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.22), 0 2px 6px rgba(0,0,0,0.5);
    }
    .brand-die::after {
      content: "";
      width: 7px;
      height: 7px;
      border-radius: 2px;
      background: #f5f5f7;
    }
    .nav-links {
      display: flex;
      align-items: center;
      gap: 28px;
      font-size: 0.79rem;
      color: var(--ink-2);
      letter-spacing: -0.005em;
    }
    .nav-links a { transition: color 0.2s ease; }
    .nav-links a:hover { color: var(--ink-1); }
    .nav-cta-group {
      display: flex;
      align-items: center;
      gap: 14px;
    }
    .nav-gh {
      font-size: 0.78rem;
      color: var(--ink-2);
      transition: color 0.2s ease;
    }
    .nav-gh:hover { color: var(--ink-1); }
    .nav-pill {
      padding: 5px 14px;
      border-radius: 980px;
      background: #f5f5f7;
      color: #000000;
      font-size: 0.76rem;
      font-weight: 600;
      letter-spacing: -0.01em;
      transition: transform 0.22s var(--ease-spring), background 0.2s ease;
    }
    .nav-pill:hover { background: #ffffff; transform: scale(1.03); }

    /* === Hero Cinema Stage === */
    .hero {
      position: relative;
      padding: 52px 24px 76px;
      overflow: hidden;
      background:
        radial-gradient(ellipse 80% 52% at 50% -8%, rgba(124, 196, 248, 0.11), transparent 68%),
        radial-gradient(ellipse 60% 45% at 50% 68%, rgba(255, 255, 255, 0.035), transparent 72%),
        #000000;
    }
    #wafer-canvas {
      position: absolute;
      inset: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      opacity: 0.72;
      -webkit-mask-image: radial-gradient(ellipse 46% 38% at 50% 28%, rgba(0,0,0,0.18) 0%, rgba(0,0,0,1) 78%);
      mask-image: radial-gradient(ellipse 46% 38% at 50% 28%, rgba(0,0,0,0.18) 0%, rgba(0,0,0,1) 78%);
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
      background: rgba(255, 255, 255, 0.055);
      border: 0.5px solid rgba(255, 255, 255, 0.14);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.12);
      font-size: 0.76rem;
      font-weight: 500;
      letter-spacing: 0.02em;
      color: #d2d2d7;
      margin-bottom: 18px;
    }
    .kicker-dot {
      width: 6px;
      height: 6px;
      border-radius: 50%;
      background: #57c98c;
      box-shadow: 0 0 10px #57c98c;
    }
    .hero h1 {
      margin: 0 auto 18px;
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
      font-size: clamp(1.02rem, 1.4vw, 1.18rem);
      line-height: 1.48;
      letter-spacing: -0.011em;
      color: var(--ink-2);
      font-weight: 400;
    }
    .hero-lead strong {
      color: var(--ink-1);
      font-weight: 500;
    }
    .hero-actions {
      display: flex;
      justify-content: center;
      flex-wrap: wrap;
      gap: 14px;
      margin-bottom: 44px;
    }
    .btn-primary {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 24px;
      border-radius: 980px;
      background: #f5f5f7;
      color: #000000;
      font-size: 0.92rem;
      font-weight: 600;
      letter-spacing: -0.012em;
      box-shadow:
        0 1px 2px rgba(0, 0, 0, 0.35),
        0 8px 20px rgba(255, 255, 255, 0.08);
      transition: transform 0.26s var(--ease-spring), background 0.2s ease, box-shadow 0.26s ease;
    }
    .btn-primary:hover {
      background: #ffffff;
      transform: translateY(-1.5px) scale(1.015);
      box-shadow: 0 4px 12px rgba(0, 0, 0, 0.45), 0 12px 28px rgba(255, 255, 255, 0.14);
    }
    .btn-glass {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 22px;
      border-radius: 980px;
      background: rgba(255, 255, 255, 0.07);
      color: var(--ink-1);
      border: 0.5px solid rgba(255, 255, 255, 0.18);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.12), 0 4px 14px rgba(0, 0, 0, 0.35);
      font-size: 0.92rem;
      font-weight: 500;
      letter-spacing: -0.01em;
      transition: transform 0.26s var(--ease-spring), background 0.2s ease, border-color 0.2s ease;
    }
    .btn-glass:hover {
      background: rgba(255, 255, 255, 0.12);
      border-color: rgba(255, 255, 255, 0.30);
      transform: translateY(-1.5px);
    }

    /* === 3D Physical Four-Volume Hardcover Shelf === */
    .hero-shelf {
      position: relative;
      z-index: 2;
      max-width: 1180px;
      margin: 0 auto;
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 28px;
      perspective: 2200px;
      padding: 12px 12px 24px;
    }
    .shelf-book {
      position: relative;
      display: flex;
      flex-direction: column;
      align-items: center;
      outline: none;
      --fan: 1;
    }
    .book-3d {
      position: relative;
      width: 100%;
      max-width: 236px;
      aspect-ratio: 1400 / 1850;
      transform-style: preserve-3d;
      transform:
        translateY(calc(var(--base-ty, 0px) * var(--fan)))
        rotateY(calc(var(--base-ry, 0deg) * var(--fan)))
        rotateX(3.5deg);
      transition: transform 0.65s var(--ease-spring);
      will-change: transform;
    }
    .shelf-book:hover .book-3d,
    .shelf-book:focus-visible .book-3d {
      transform: translate3d(0, -18px, 46px) rotateY(-13deg) rotateX(4deg);
    }
    .book-front {
      position: absolute;
      inset: 0;
      border-radius: 3px 7px 7px 3px;
      overflow: hidden;
      transform: translateZ(13px);
      background: #070b12;
      box-shadow:
        inset 0 0 0 0.5px rgba(255, 255, 255, 0.20),
        inset 0 1px 0 rgba(255, 255, 255, 0.25);
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
        rgba(255, 255, 255, 0.24) 0%,
        rgba(255, 255, 255, 0.06) 1.4%,
        rgba(0, 0, 0, 0.52) 3.0%,
        rgba(255, 255, 255, 0.12) 4.4%,
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
        circle 220px at var(--gx, 50%) var(--gy, 30%),
        rgba(255, 255, 255, 0.20),
        transparent 70%
      );
      transition: opacity 0.35s ease;
    }
    .shelf-book:hover .book-sheen,
    .vol-showcase:hover .book-sheen {
      opacity: 1;
    }
    /* Left 3D Hardcover Spine */
    .book-spine {
      position: absolute;
      top: 0;
      bottom: 0;
      left: -13px;
      width: 26px;
      background: linear-gradient(90deg, #05080e 0%, #101928 52%, #070c14 100%);
      border-top: 0.5px solid rgba(255, 255, 255, 0.18);
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
      background: var(--vol-hex);
    }
    .spine-vol, .spine-title {
      writing-mode: vertical-rl;
      font-size: 7.5px;
      letter-spacing: 0.14em;
      font-weight: 600;
      color: rgba(245, 245, 247, 0.72);
      white-space: nowrap;
    }
    .spine-vol { color: var(--vol-hex); }
    /* Right 3D Archival Paper Page-Block Fore-Edge */
    .book-pages {
      position: absolute;
      top: 3px;
      bottom: 3px;
      right: -12px;
      width: 24px;
      transform: rotateY(90deg);
      background:
        linear-gradient(90deg, rgba(0,0,0,0.32), transparent 22%, rgba(0,0,0,0.22) 100%),
        repeating-linear-gradient(90deg, #e7e4dc 0px, #e7e4dc 1.5px, #cfcac0 1.5px, #cfcac0 2.5px);
      border-radius: 0 2px 2px 0;
    }
    .book-back {
      position: absolute;
      inset: 0;
      border-radius: 3px 7px 7px 3px;
      background: #060910;
      transform: translateZ(-13px);
      box-shadow: 0 28px 50px rgba(0, 0, 0, 0.85);
    }
    /* Realistic Multi-Layer Studio Floor Shadow */
    .book-floor-shadow {
      width: 82%;
      height: 22px;
      margin-top: 22px;
      border-radius: 50%;
      background:
        radial-gradient(ellipse at center, rgba(0, 0, 0, 0.92) 0%, rgba(0, 0, 0, 0.55) 48%, transparent 76%);
      filter: blur(8px);
      transition: transform 0.65s var(--ease-spring), opacity 0.65s ease, background 0.45s ease;
    }
    .shelf-book:hover .book-floor-shadow {
      transform: scaleX(1.08) translateY(6px);
      background: radial-gradient(
        ellipse at center,
        rgba(var(--vol-rgb), 0.34) 0%,
        rgba(0, 0, 0, 0.78) 52%,
        transparent 78%
      );
    }
    .shelf-caption {
      margin-top: 12px;
      display: flex;
      flex-direction: column;
      align-items: center;
      gap: 4px;
      text-align: center;
    }
    .shelf-vol-pill {
      font-size: 0.80rem;
      font-weight: 600;
      letter-spacing: -0.01em;
      color: var(--ink-1);
      transition: color 0.25s ease;
    }
    .shelf-book:hover .shelf-vol-pill { color: var(--vol-hex); }
    .shelf-metrics {
      font-family: var(--mono);
      font-size: 0.71rem;
      color: var(--ink-3);
    }

    /* === Section Shared Scaffolding === */
    .section {
      position: relative;
      padding: 104px 24px;
      scroll-margin-top: 56px;
      border-top: 0.5px solid var(--hairline);
    }
    .section-elevated { background: var(--bg-elevated); }
    .container {
      max-width: 1200px;
      margin: 0 auto;
    }
    .section-header {
      max-width: 780px;
      margin-bottom: 60px;
    }
    .section-eyebrow {
      font-size: 0.80rem;
      font-weight: 600;
      letter-spacing: 0.02em;
      color: #86868b;
      margin-bottom: 10px;
    }
    .section-title {
      margin: 0 0 16px;
      font-size: clamp(2rem, 4.2vw, 3.35rem);
      font-weight: 600;
      line-height: 1.08;
      letter-spacing: -0.032em;
      color: var(--ink-1);
    }
    .section-title span { color: #86868b; }
    .section-desc {
      margin: 0;
      font-size: clamp(1rem, 1.35vw, 1.16rem);
      line-height: 1.52;
      letter-spacing: -0.01em;
      color: var(--ink-2);
    }

    /* === Spotlight Card Physics (Subtle Cursor-Tracked Specular Light) === */
    .spotlight-card {
      position: relative;
      background: var(--bg-card);
      border-radius: 28px;
      border: 0.5px solid rgba(255, 255, 255, 0.10);
      box-shadow:
        inset 0 1px 0 rgba(255, 255, 255, 0.11),
        var(--shadow-ambient);
      overflow: hidden;
    }
    .spotlight-card::before {
      content: "";
      position: absolute;
      inset: 0;
      pointer-events: none;
      opacity: 0;
      background: radial-gradient(
        640px circle at var(--mx, 50%) var(--my, 0%),
        rgba(255, 255, 255, 0.055),
        transparent 45%
      );
      transition: opacity 0.4s ease;
    }
    .spotlight-card:hover::before { opacity: 1; }

    /* === Interactive 6-Tier Cross-OS Silicon-to-Cloud Visualizer === */
    .stack-explorer {
      padding: 36px;
      display: grid;
      grid-template-columns: 290px 1fr;
      gap: 36px;
      align-items: start;
    }
    .stack-rail {
      display: flex;
      flex-direction: column;
      gap: 6px;
    }
    .rail-controls {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 10px;
      padding: 0 8px;
    }
    .rail-title {
      font-family: var(--mono);
      font-size: 0.70rem;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--ink-3);
    }
    .autoplay-btn {
      background: rgba(255, 255, 255, 0.07);
      border: 0.5px solid rgba(255, 255, 255, 0.15);
      color: var(--ink-2);
      border-radius: 980px;
      padding: 4px 11px;
      font-size: 0.70rem;
      font-weight: 500;
      cursor: pointer;
      transition: background 0.2s ease, color 0.2s ease;
    }
    .autoplay-btn:hover { background: rgba(255, 255, 255, 0.13); color: var(--ink-1); }

    .tier-btn {
      position: relative;
      width: 100%;
      text-align: left;
      padding: 13px 16px 15px;
      border-radius: 16px;
      border: 0.5px solid transparent;
      background: transparent;
      color: var(--ink-2);
      cursor: pointer;
      display: grid;
      grid-template-columns: 28px 1fr;
      align-items: center;
      gap: 8px;
      transition: background 0.25s ease, color 0.25s ease, border-color 0.25s ease;
    }
    .tier-btn:hover {
      background: rgba(255, 255, 255, 0.04);
      color: var(--ink-1);
    }
    .tier-btn.active {
      background: rgba(255, 255, 255, 0.075);
      border-color: rgba(255, 255, 255, 0.14);
      color: var(--ink-1);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.10), 0 8px 20px rgba(0, 0, 0, 0.35);
    }
    .tier-num {
      font-family: var(--mono);
      font-size: 0.74rem;
      color: var(--ink-3);
    }
    .tier-btn.active .tier-num { color: #7cc4f8; }
    .tier-label {
      font-size: 0.88rem;
      font-weight: 600;
      letter-spacing: -0.012em;
    }
    .tier-progress {
      grid-column: 1 / -1;
      height: 2px;
      border-radius: 2px;
      background: rgba(255, 255, 255, 0.08);
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
      background: linear-gradient(90deg, #7cc4f8, #f5f5f7);
      transition: width 0.1s linear;
    }

    .stack-stage {
      min-width: 0;
      transition: opacity 0.26s ease, transform 0.36s var(--ease-out-expo);
    }
    .stack-stage.switching {
      opacity: 0;
      transform: translateY(6px);
    }
    .stage-top {
      padding-bottom: 22px;
      margin-bottom: 24px;
      border-bottom: 0.5px solid var(--hairline);
    }
    .stage-top h3 {
      margin: 0 0 8px;
      font-size: 1.45rem;
      font-weight: 600;
      letter-spacing: -0.022em;
      color: var(--ink-1);
    }
    .stage-top p {
      margin: 0;
      font-size: 0.95rem;
      line-height: 1.52;
      color: var(--ink-2);
    }
    /* Animated SVG Signal Bus Bar */
    .signal-bus {
      width: 100%;
      height: 26px;
      margin-bottom: 18px;
      display: block;
    }
    .signal-pulse-line {
      stroke-dasharray: 90 420;
      animation: busFlow 3.4s linear infinite;
    }
    @keyframes busFlow {
      from { stroke-dashoffset: 510; }
      to { stroke-dashoffset: 0; }
    }

    .os-compare-grid {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 16px;
    }
    .os-tile {
      padding: 20px 22px;
      border-radius: 20px;
      background: rgba(255, 255, 255, 0.03);
      border: 0.5px solid rgba(255, 255, 255, 0.085);
      box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.06);
      display: flex;
      flex-direction: column;
      gap: 12px;
      transition: border-color 0.25s ease, background 0.25s ease;
    }
    .os-tile:hover {
      background: rgba(255, 255, 255, 0.048);
      border-color: rgba(var(--os-rgb), 0.45);
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
      background: var(--os-hex);
      box-shadow: 0 0 10px rgba(var(--os-rgb), 0.7);
    }
    .os-jump {
      font-size: 0.74rem;
      font-weight: 500;
      color: var(--ink-2);
      transition: color 0.2s ease;
    }
    .os-tile:hover .os-jump { color: var(--os-hex); }
    .os-prims {
      display: flex;
      flex-wrap: wrap;
      gap: 6px;
    }
    .prim-chip {
      font-family: var(--mono);
      font-size: 0.70rem;
      padding: 3px 8px;
      border-radius: 6px;
      background: rgba(var(--os-rgb), 0.10);
      border: 0.5px solid rgba(var(--os-rgb), 0.28);
      color: var(--ink-1);
    }
    .os-row-label {
      font-family: var(--mono);
      font-size: 0.65rem;
      text-transform: uppercase;
      letter-spacing: 0.08em;
      color: var(--ink-3);
      display: block;
      margin-bottom: 3px;
    }
    .os-inv, .os-break {
      margin: 0;
      font-size: 0.82rem;
      line-height: 1.46;
      color: #d2d2d7;
    }
    .os-break { color: var(--ink-2); }

    /* === Editorial Volume Showcases (#volumes) === */
    .volumes-stack {
      display: flex;
      flex-direction: column;
      gap: 36px;
    }
    .vol-showcase {
      padding: 48px 52px;
      display: grid;
      grid-template-columns: 300px 1fr;
      gap: 56px;
      align-items: center;
      background:
        radial-gradient(520px circle at 16% 50%, rgba(var(--vol-rgb), 0.075), transparent 70%),
        var(--bg-card);
    }
    .vol-visual-col {
      display: flex;
      justify-content: center;
      perspective: 1800px;
    }
    .showcase-book-stage {
      display: flex;
      flex-direction: column;
      align-items: center;
      width: 240px;
    }
    .showcase-3d {
      max-width: 240px;
      transform: rotateY(-16deg) rotateX(4deg);
      transition: transform 0.65s var(--ease-spring);
    }
    .vol-showcase:hover .showcase-3d {
      transform: translate3d(0, -10px, 28px) rotateY(-8deg) rotateX(2deg);
    }
    .showcase-shadow {
      margin-top: 26px;
      background: radial-gradient(
        ellipse at center,
        rgba(var(--vol-rgb), 0.28) 0%,
        rgba(0, 0, 0, 0.86) 52%,
        transparent 78%
      );
    }
    .vol-eyebrow {
      font-size: 0.78rem;
      font-weight: 600;
      letter-spacing: 0.02em;
      color: var(--vol-hex);
      margin-bottom: 8px;
    }
    .vol-title {
      margin: 0 0 8px;
      font-size: clamp(1.75rem, 3vw, 2.45rem);
      font-weight: 600;
      letter-spacing: -0.03em;
      line-height: 1.1;
      color: var(--ink-1);
    }
    .vol-subheadline {
      margin: 0 0 14px;
      font-size: 1.12rem;
      font-weight: 500;
      letter-spacing: -0.015em;
      color: #d2d2d7;
    }
    .vol-blurb {
      margin: 0 0 22px;
      font-size: 0.95rem;
      line-height: 1.58;
      color: var(--ink-2);
    }
    .spec-parts-list {
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 8px 18px;
      margin-bottom: 26px;
    }
    .spec-part-item {
      display: flex;
      align-items: baseline;
      gap: 8px;
      font-size: 0.80rem;
      line-height: 1.42;
      color: #d2d2d7;
    }
    .spec-dot {
      flex-shrink: 0;
      width: 5px;
      height: 5px;
      border-radius: 50%;
      background: var(--vol-hex);
      transform: translateY(-1px);
    }
    .vol-stat-strip {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 12px;
      padding: 16px 0;
      margin-bottom: 26px;
      border-top: 0.5px solid var(--hairline);
      border-bottom: 0.5px solid var(--hairline);
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
    .span-7 { grid-column: span 7; }
    .span-5 { grid-column: span 5; }
    .span-4 { grid-column: span 4; }
    .bento-metric {
      font-size: clamp(2.6rem, 4.8vw, 4rem);
      font-weight: 600;
      letter-spacing: -0.04em;
      line-height: 1;
      color: var(--ink-1);
    }
    .bento-tile h3 {
      margin: 0 0 8px;
      font-size: 1.24rem;
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
      border-radius: 14px;
      background: rgba(255, 255, 255, 0.025);
      border: 0.5px solid rgba(255, 255, 255, 0.08);
      padding: 14px;
    }
    .ortho-trace {
      stroke-dasharray: 8 6;
      animation: orthoMove 6s linear infinite;
    }
    @keyframes orthoMove {
      to { stroke-dashoffset: -84; }
    }

    /* === Scroll Reveal Choreography === */
    .reveal {
      opacity: 0;
      transform: translateY(24px);
      transition: opacity 0.8s var(--ease-out-expo), transform 0.8s var(--ease-out-expo);
    }
    .reveal.in-view {
      opacity: 1;
      transform: translateY(0);
    }

    /* === Footer === */
    .site-footer {
      border-top: 0.5px solid var(--hairline);
      background: #050507;
      padding: 64px 24px 48px;
      color: var(--ink-3);
      font-size: 0.80rem;
    }
    .footer-grid {
      max-width: 1200px;
      margin: 0 auto 44px;
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
      padding-top: 24px;
      border-top: 0.5px solid var(--hairline);
      display: flex;
      justify-content: space-between;
      flex-wrap: wrap;
      gap: 12px;
    }

    /* === Responsive Breakpoints === */
    @media (max-width: 1024px) {
      .hero-shelf {
        grid-template-columns: repeat(2, minmax(0, 1fr));
        max-width: 600px;
        gap: 36px 28px;
      }
      .stack-explorer { grid-template-columns: 1fr; padding: 26px; }
      .stack-rail {
        flex-direction: row;
        overflow-x: auto;
        padding-bottom: 6px;
      }
      .rail-controls { display: none; }
      .tier-btn { min-width: 195px; }
      .vol-showcase {
        grid-template-columns: 1fr;
        padding: 36px 28px;
        gap: 34px;
      }
      .span-7, .span-5, .span-4 { grid-column: span 12; }
      .footer-grid { grid-template-columns: 1fr 1fr; }
    }
    @media (max-width: 640px) {
      .nav-links, .nav-gh { display: none; }
      .hero { padding: 56px 18px 64px; }
      .hero-shelf { gap: 28px 18px; }
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
  <nav class="local-nav" aria-label="Series Navigation">
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
        <span>Four Complete Monographs · 1,457 Print Pages · Open Access</span>
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
        <a class="btn-glass" href="#stack">Compare Trust Chains</a>
      </div>
    </div>

    <div class="hero-shelf" id="hero-shelf">
      ${heroBooksHtml}
    </div>
  </header>

  <section class="section section-elevated" id="stack">
    <div class="container">
      <div class="section-header reveal">
        <div class="section-eyebrow">Cross-Platform Architecture</div>
        <h2 class="section-title">Six links in the chain. <span>Four radically different bets.</span></h2>
        <p class="section-desc">
          Step through each hardware and software boundary from power-on reset to confidential AI enclaves to inspect how every platform enforces its invariant and where in-the-wild exploit chains break through.
        </p>
      </div>

      <div class="stack-explorer spotlight-card reveal">
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
            <line x1="8" y1="13" x2="792" y2="13" stroke="rgba(255,255,255,0.09)" stroke-width="1.2"/>
            <line class="signal-pulse-line" x1="8" y1="13" x2="792" y2="13" stroke="url(#busGrad)" stroke-width="2"/>
            <circle cx="100" cy="13" r="3.5" fill="#d4a843"/>
            <circle cx="300" cy="13" r="3.5" fill="#7cc4f8"/>
            <circle cx="500" cy="13" r="3.5" fill="#e5954b"/>
            <circle cx="700" cy="13" r="3.5" fill="#57c98c"/>
            <defs>
              <linearGradient id="busGrad" x1="0" y1="0" x2="800" y2="0" gradientUnits="userSpaceOnUse">
                <stop offset="0%" stop-color="#d4a843" stop-opacity="0"/>
                <stop offset="35%" stop-color="#7cc4f8"/>
                <stop offset="70%" stop-color="#57c98c"/>
                <stop offset="100%" stop-color="#57c98c" stop-opacity="0"/>
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

  <section class="section section-elevated" id="craft">
    <div class="container">
      <div class="section-header reveal">
        <div class="section-eyebrow">Precision Engineering</div>
        <h2 class="section-title">Mechanically verified. <span>Down to every pixel and citation.</span></h2>
        <p class="section-desc">
          Technical books rot when diagrams drift, links break, or prose dissolves into slide bullets. All four monographs are compiled and audited by a deterministic build suite on every commit.
        </p>
      </div>

      <div class="bento-grid">
        <div class="bento-tile spotlight-card span-7 reveal">
          <div>
            <div class="section-eyebrow">Collision-Verified Schematics</div>
            <h3>266 programmatic vector diagrams</h3>
            <p>
              Every architecture schematic is authored in Python atop a custom layout engine enforcing strict orthogonal routing, row-synchronized split domains, masked edge labels, and automated seven-way collision assertions.
            </p>
          </div>
          <svg class="bento-diagram" viewBox="0 0 620 128" fill="none" aria-hidden="true">
            <rect x="16" y="26" width="148" height="76" rx="10" fill="rgba(124,196,248,0.08)" stroke="rgba(124,196,248,0.45)" stroke-width="1.2"/>
            <text x="90" y="56" fill="#f5f5f7" font-size="11" font-weight="600" text-anchor="middle" font-family="ui-monospace, monospace">SILICON ROOT</text>
            <text x="90" y="76" fill="#86868b" font-size="9.5" text-anchor="middle" font-family="ui-monospace, monospace">UID / ECID / VCEK</text>

            <rect x="236" y="26" width="148" height="76" rx="10" fill="rgba(212,168,67,0.08)" stroke="rgba(212,168,67,0.45)" stroke-width="1.2"/>
            <text x="310" y="56" fill="#f5f5f7" font-size="11" font-weight="600" text-anchor="middle" font-family="ui-monospace, monospace">EL2 / VTL1 / SPTM</text>
            <text x="310" y="76" fill="#86868b" font-size="9.5" text-anchor="middle" font-family="ui-monospace, monospace">Stage-2 Page Lock</text>

            <rect x="456" y="26" width="148" height="76" rx="10" fill="rgba(87,201,140,0.08)" stroke="rgba(87,201,140,0.45)" stroke-width="1.2"/>
            <text x="530" y="56" fill="#f5f5f7" font-size="11" font-weight="600" text-anchor="middle" font-family="ui-monospace, monospace">ATTESTED TEE</text>
            <text x="530" y="76" fill="#86868b" font-size="9.5" text-anchor="middle" font-family="ui-monospace, monospace">PCC / SVSM / TIE</text>

            <line x1="164" y1="64" x2="236" y2="64" stroke="rgba(255,255,255,0.18)" stroke-width="1.4"/>
            <line class="ortho-trace" x1="164" y1="64" x2="236" y2="64" stroke="#7cc4f8" stroke-width="1.8"/>
            <line x1="384" y1="64" x2="456" y2="64" stroke="rgba(255,255,255,0.18)" stroke-width="1.4"/>
            <line class="ortho-trace" x1="384" y1="64" x2="456" y2="64" stroke="#57c98c" stroke-width="1.8"/>
          </svg>
        </div>

        <div class="bento-tile spotlight-card span-5 reveal">
          <div class="bento-metric" data-count="2587">2,587</div>
          <div>
            <h3>Primary-source citations</h3>
            <p>
              Anchored directly to normative specifications, RFCs, TCG/UEFI/ARM manuals, XNU/Linux/AOSP source trees, and primary CVE advisories, audited for zero unresolved links or uncited orphans.
            </p>
          </div>
        </div>

        <div class="bento-tile spotlight-card span-4 reveal">
          <div class="bento-metric" data-count="1457">1,457</div>
          <div>
            <h3>Print-ready 7 × 9.25 in pages</h3>
            <p>
              Typeset in Georgia with KaTeX mathematical notation, proportional overflow-free tables, native PDF outlines, and full-bleed vector covers.
            </p>
          </div>
        </div>

        <div class="bento-tile spotlight-card span-4 reveal">
          <div class="bento-metric" data-count="404">404K</div>
          <div>
            <h3>Sustained monograph words</h3>
            <p>
              Written in continuous architectural prose rather than slide-deck bullets, separating local primitive validity from end-to-end system authorization.
            </p>
          </div>
        </div>

        <div class="bento-tile spotlight-card span-4 reveal">
          <div class="bento-metric">83</div>
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
          Open technical security monographs by <a href="https://paragmali.com" style="color:#f5f5f7;text-decoration:underline;text-underline-offset:3px;">${esc(registry.author)}</a>. Free to read online and download for personal and educational study under CC BY-NC-SA 4.0.
        </p>
      </div>
      <div class="footer-col">
        <h4>Web Editions</h4>
        <ul>
          <li><a href="${rootRel}windows/index.html">Vol. I · Windows</a></li>
          <li><a href="${rootRel}apple/index.html">Vol. II · Apple</a></li>
          <li><a href="${rootRel}linux/index.html">Vol. III · Linux</a></li>
          <li><a href="${rootRel}android/index.html">Vol. IV · Android</a></li>
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
      <span>Copyright © 2026 ${esc(registry.author)}. Licensed under CC BY-NC-SA 4.0. Commercial rights reserved.</span>
      <span>Built with mdBook, KaTeX, and programmatic SVG schematics.</span>
    </div>
  </footer>

  <script>
  (function () {
    var LAYERS = ${stackDataJson};
    var OS_META = [
      { key: 'windows', name: 'Vol. I · Windows', hex: '#d4a843', rgb: '212, 168, 67' },
      { key: 'apple',   name: 'Vol. II · Apple',  hex: '#7cc4f8', rgb: '124, 196, 248' },
      { key: 'linux',   name: 'Vol. III · Linux', hex: '#e5954b', rgb: '229, 149, 75' },
      { key: 'android', name: 'Vol. IV · Android',hex: '#57c98c', rgb: '87, 201, 140' }
    ];
    var reducedMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

    function escHtml(s) {
      return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    // 1. Interactive 6-Tier Stack Explorer + Auto-Cycle Progress
    var stage = document.getElementById('stack-stage');
    var titleEl = document.getElementById('stage-title');
    var sumEl = document.getElementById('stage-summary');
    var gridEl = document.getElementById('os-compare-grid');
    var btns = Array.prototype.slice.call(document.querySelectorAll('.tier-btn'));
    var toggleBtn = document.getElementById('autoplay-toggle');
    var activeIdx = 0;
    var playing = !reducedMotion;
    var DURATION = 6500;
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
            '<a class="os-tile" href="' + escHtml(layer.links[m.key]) + '" style="--os-hex:' + m.hex + '; --os-rgb:' + m.rgb + ';">' +
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
        }, 170);
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

    // 2. Cursor-Tracked Specular Sheen on 3D Books & Spotlight Bento Cards
    document.querySelectorAll('.spotlight-card').forEach(function (card) {
      card.addEventListener('pointermove', function (e) {
        var r = card.getBoundingClientRect();
        card.style.setProperty('--mx', (e.clientX - r.left) + 'px');
        card.style.setProperty('--my', (e.clientY - r.top) + 'px');
      });
    });
    document.querySelectorAll('.book-front').forEach(function (front) {
      front.addEventListener('pointermove', function (e) {
        var r = front.getBoundingClientRect();
        front.style.setProperty('--gx', ((e.clientX - r.left) / r.width * 100).toFixed(1) + '%');
        front.style.setProperty('--gy', ((e.clientY - r.top) / r.height * 100).toFixed(1) + '%');
      });
    });

    // 3. Scroll-Linked Shelf Fan Choreography & Reveal Observer
    var shelfBooks = Array.prototype.slice.call(document.querySelectorAll('.shelf-book'));
    if (!reducedMotion && shelfBooks.length) {
      function onScroll() {
        var y = Math.min(1, Math.max(0, window.scrollY / 420));
        var fan = (1 - y * 0.42).toFixed(3);
        shelfBooks.forEach(function (sb) { sb.style.setProperty('--fan', fan); });
      }
      window.addEventListener('scroll', onScroll, { passive: true });
    }

    if ('IntersectionObserver' in window) {
      var io = new IntersectionObserver(function (entries) {
        entries.forEach(function (en) {
          if (en.isIntersecting) {
            en.target.classList.add('in-view');
            io.unobserve(en.target);
          }
        });
      }, { threshold: 0.12 });
      document.querySelectorAll('.reveal').forEach(function (el) { io.observe(el); });
    } else {
      document.querySelectorAll('.reveal').forEach(function (el) { el.classList.add('in-view'); });
    }

    // 4. 60fps Wafer-Die Orthogonal Signal Canvas in Hero
    var canvas = document.getElementById('wafer-canvas');
    if (canvas && canvas.getContext && !reducedMotion) {
      var ctx = canvas.getContext('2d');
      var cw = 0, ch = 0, dpr = Math.min(2, window.devicePixelRatio || 1);
      var colors = ['#d4a843', '#7cc4f8', '#e5954b', '#57c98c'];
      var traces = [];

      function resize() {
        var rect = canvas.parentElement.getBoundingClientRect();
        cw = rect.width;
        ch = rect.height;
        canvas.width = cw * dpr;
        canvas.height = ch * dpr;
        ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
        traces = [];
        var cols = Math.max(8, Math.floor(cw / 120));
        for (var i = 0; i < cols; i++) {
          var x = ((i + 0.5) / cols) * cw;
          traces.push({
            x: x,
            jog: (i % 2 === 0 ? 1 : -1) * 28,
            jogY: ch * (0.32 + (i % 3) * 0.14),
            pos: Math.random() * ch,
            speed: 0.45 + (i % 4) * 0.18,
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
            ctx.strokeStyle = 'rgba(255, 255, 255, 0.032)';
            ctx.beginPath();
            ctx.moveTo(t.x, ch);
            ctx.lineTo(t.x, t.jogY + 24);
            ctx.lineTo(t.x + t.jog, t.jogY);
            ctx.lineTo(t.x + t.jog, 0);
            ctx.stroke();

            t.pos -= t.speed;
            if (t.pos < -80) t.pos = ch + 60;
            var py = t.pos;
            var px = py > t.jogY + 24 ? t.x : (py < t.jogY ? t.x + t.jog : t.x + t.jog * (1 - (py - t.jogY) / 24));
            var grad = ctx.createRadialGradient(px, py, 0, px, py, 20);
            grad.addColorStop(0, t.col + '33');
            grad.addColorStop(1, t.col + '00');
            ctx.fillStyle = grad;
            ctx.beginPath();
            ctx.arc(px, py, 20, 0, Math.PI * 2);
            ctx.fill();

            ctx.fillStyle = t.col;
            ctx.beginPath();
            ctx.arc(px, py, 1.6, 0, Math.PI * 2);
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
  // Write both root book/index.html AND book/series/index.html so both /trust-chain/ and /trust-chain/series/ serve the showcase
  writeFileSync(path.join(bookDir, 'index.html'), renderSeriesPortalHtml(registry, ''), 'utf8');
  const seriesDir = path.join(bookDir, 'series');
  mkdirSync(seriesDir, { recursive: true });
  writeFileSync(path.join(seriesDir, 'index.html'), renderSeriesPortalHtml(registry, '../'), 'utf8');
}
