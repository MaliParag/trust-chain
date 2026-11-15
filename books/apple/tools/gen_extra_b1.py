#!/usr/bin/env python3
"""
Batch 1 standalone SVG generator for Chapters 1-5 (Volume II: The Apple Trust Chain).
Generates 5 collision-verified architectural diagrams into books/apple/src/diagrams/:
  - 01-extra-image4-der-tree.svg
  - 02-extra-localpolicy-hash-chain.svg
  - 03-extra-sks-keybag-uid-kdf.svg
  - 04-extra-sptm-frame-retyping.svg
  - 05-extra-dsc-pac-slide-pointers.svg
"""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "tools")))
from diagram_lib import (
    build_fan_bands,
    build_split_domains,
    build_vertical_flow,
)

DIAG_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src", "diagrams"))


def P(name: str) -> str:
    return os.path.join(DIAG_DIR, name)


def gen_01_image4_der_tree():
    build_fan_bands(
        P("01-extra-image4-der-tree.svg"),
        "Image4 (IMG4) ASN.1 DER Verification Graph: IM4P, IM4M, and IM4R",
        [
            [
                {
                    "id": "img4",
                    "tag": "Top-Level ITU-T X.690 DER SEQUENCE",
                    "title": "IMG4 Container := SEQUENCE { IA5String 'IMG4', IM4P, [0] IM4M, [1] IM4R (opt) }",
                    "body": "Canonical Distinguished Encoding Rules forbid variable-length BER padding and parser-verifier ambiguity",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "im4p",
                    "tag": "Universal Payload · IM4P",
                    "title": "Firmware & OS Object",
                    "body": "4CC tag ('illb', 'ibot', 'sepi', 'krnl', 'sptm', 'txm', 'ltrs'), build string, LZFSE/BVX2 data, optional GID KBAG",
                    "theme": "teal",
                },
                {
                    "id": "im4m",
                    "tag": "Personalized Ticket · IM4M",
                    "title": "Signed Manifest (MANB)",
                    "body": "SET of MANP chip constraints + OBJP per-component SHA-384 digests + RSA/ECDSA signature + X.509 cert chain",
                    "theme": "amber",
                },
                {
                    "id": "im4r",
                    "tag": "Restore Nonce · IM4R",
                    "title": "Boot Nonce Seed (BNCN)",
                    "body": "8-byte SEP/NVRAM generator g committed before restore; Boot ROM / LLB hashes SHA-384(g) == MANP.BNCH",
                    "theme": "purple",
                },
            ],
            [
                {
                    "id": "hash_gate",
                    "tag": "Digest Gate",
                    "title": "SHA-384(IM4P) == OBJP.DGST",
                    "body": "Verifies exact 4CC tag match, EPRO/ESEC security flags, and full payload integrity in SRAM/DRAM",
                    "theme": "white",
                },
                {
                    "id": "fuse_gate",
                    "tag": "Silicon Identity Gate",
                    "title": "MANP == Live SoC Fuses",
                    "body": "Matches 64-bit ECID, CHIP, BORD, SDOM, CEPO epoch, CPRO production fuse, and Apple Root CA PK hash",
                    "theme": "white",
                },
                {
                    "id": "replay_gate",
                    "tag": "Anti-Replay Gate",
                    "title": "SHA-384(BNCN) == MANP.BNCH",
                    "body": "Invalidates captured historical SHSH/IM4M tickets as soon as SEP rotates the hardware nonce slot",
                    "theme": "white",
                },
            ],
            [
                {
                    "id": "verdict",
                    "tag": "Conjunction Gate in SecureROM / LLB / iBoot",
                    "title": "Admit & Map Next Stage Executable iff Signature & Fuses & Digest & Nonce All Hold",
                    "body": "Any mismatch scrubs staging memory and traps directly into USB DFU or paired One True Recovery (1TR)",
                    "theme": "green",
                }
            ],
        ],
        [
            ("img4", "im4p", "field [1]", "teal", False),
            ("img4", "im4m", "tag [0]", "amber", False),
            ("img4", "im4r", "tag [1]", "purple", True),
            ("im4p", "hash_gate", "SHA-384", "teal", False),
            ("im4m", "fuse_gate", "MANB / MANP", "amber", False),
            ("im4r", "replay_gate", "generator g", "purple", False),
            ("hash_gate", "verdict", "digest ok", "green", False),
            ("fuse_gate", "verdict", "PK + fuses ok", "green", False),
            ("replay_gate", "verdict", "fresh BNCH", "green", False),
        ],
        footer="IM4P binaries stay identical on Apple CDNs while tiny IM4M manifests bind authorization to one ECID and nonce.",
    )


def gen_02_localpolicy_hash_chain():
    build_fan_bands(
        P("02-extra-localpolicy-hash-chain.svg"),
        "Apple Silicon Mac LocalPolicy Image4 Schema & xART Anti-Replay Binding",
        [
            [
                {
                    "id": "root",
                    "tag": "Per-Volume-Group Image4 Manifest (Signed by SEP OIHR Key Under BAA Attestation)",
                    "title": "LocalPolicy.im4m in /System/Volumes/Preboot/<VG-UUID>/boot/<BootHash>/.../LocalPolicy",
                    "body": "Evaluated by LLB and iBoot before XNU starts; downgrade signing requires PMU physical hold into paired 1TR + owner SecureToken",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "nonces",
                    "tag": "Anti-Replay Nonce Hashes",
                    "title": "lpnh · rpnh · spnh",
                    "body": "SHA-384 hashes of secret LPN, RPN, and SPN nonces inside SEP Secure Storage (xART); prevents replaying old policies",
                    "theme": "purple",
                },
                {
                    "id": "targets",
                    "tag": "Boot Object Pinning",
                    "title": "nsih · coih · vuid",
                    "body": "Pins macOS OS Image4 manifest SHA-384 (nsih) or CustomOS Mach-O manifest hash (coih, e.g. m1n1) to Volume Group UUID",
                    "theme": "teal",
                },
                {
                    "id": "modes",
                    "tag": "Security Mode & CSR Flags",
                    "title": "smb0..smb4 · sip0..sip3",
                    "body": "smb0 Reduced, smb1 Permissive, smb2 AuxKC kexts, smb3 MDM; sip0 csr_config_t, sip1 SSV off, sip2 CTRR off, sip3 boot-args",
                    "theme": "amber",
                },
                {
                    "id": "auxkc",
                    "tag": "Third-Party Kext Chain",
                    "title": "auxp · auxi/aukh · auxr",
                    "body": "Binds User-Authorized Kext List hash (auxp), SEP-signed AuxKC IM4M hash (auxi/aukh), and filtered receipt hash (auxr)",
                    "theme": "green",
                },
            ],
            [
                {
                    "id": "sep_xart",
                    "tag": "Hardware State Enforcement Across LLB, iBoot, and SEP Secure Storage Component",
                    "title": "SEP Rotates Secret LPN -> lpnh' on Every Policy Mutation & Erases LPN/RPN on Find My Lock",
                    "body": "Backing up an older Permissive LocalPolicy file fails at boot because SHA-384(LPN_current) != lpnh_replayed",
                    "theme": "red",
                }
            ],
        ],
        [
            ("root", "nonces", "nonce 4CCs", "purple", False),
            ("root", "targets", "image 4CCs", "teal", False),
            ("root", "modes", "policy 4CCs", "amber", False),
            ("root", "auxkc", "kext 4CCs", "green", False),
            ("nonces", "sep_xart", "xART verify", "purple", False),
            ("targets", "sep_xart", "LLB match", "teal", False),
            ("modes", "sep_xart", "CTRR / CSR", "amber", False),
            ("auxkc", "sep_xart", "UAKL lock", "green", False),
        ],
        footer="Each APFS volume group maintains an independent LocalPolicy so Permissive Linux never weakens sibling Full Security macOS.",
    )


def gen_03_sks_keybag_uid_kdf():
    build_split_domains(
        P("03-extra-sks-keybag-uid-kdf.svg"),
        "SEP Hardware UID/GID Key Derivation, SKS Keyhandles, and xART Lockboxes",
        {
            "label": "SEP Silicon & L4-Derived sepOS Tasks",
            "theme": "green",
            "cards": [
                {
                    "tag": "eFuse & Hardware KDF Engine",
                    "title": "256-bit Silicon UID & GID",
                    "body": "Wired exclusively to counter-mode AES / CMAC KDF hardware; raw UID bits never enter SEP CPU registers or SRAM",
                    "theme": "amber",
                },
                {
                    "tag": "sepOS User Task (endpoint 0x12)",
                    "title": "sks (AppleKeyStore_SEP)",
                    "body": "Receives opaque KDF keyhandles, enforces passcode tangling (~80 ms/try), and manages System/Escrow keybag slots",
                    "theme": "white",
                    "in_edge": "opaque keyhandle",
                },
                {
                    "tag": "sepOS Biometric & Art Tasks",
                    "title": "sep_biometric & sep_art",
                    "body": "Matches Touch ID / Face ID / Optic ID vectors and commits monotonic state before releasing SKS key slots",
                    "theme": "white",
                    "in_edge": "bio token / epoch",
                },
            ],
        },
        {
            "label": "Untrusted AP (XNU EL1) & Paired Storage",
            "theme": "stone",
            "cards": [
                {
                    "tag": "Tamper-Detecting Companion IC / ANS",
                    "title": "Secure Storage & ART / xART",
                    "body": "Increments attempt counter BEFORE passcode KDF check; erases lockbox entropy upon exceeding retry limit",
                    "theme": "purple",
                },
                {
                    "tag": "XNU EL1 Driver & Mailbox",
                    "title": "AKF 64-bit FIFO & AppleKeyStore",
                    "body": "Sends RTKit/AKF opcodes + DART-fenced shmem descriptors over DH-encrypted mailbox session; holds zero raw UID keys",
                    "theme": "white",
                    "in_edge": "xART MAC blobs",
                },
                {
                    "tag": "Inline Storage & User Vaults",
                    "title": "ANS AES-XTS & secd Keychain",
                    "body": "Receives ephemerally wrapped per-file media keys or signed digests when protection class (AFU / Class A) is unlocked",
                    "theme": "teal",
                    "in_edge": "wrapped class key",
                },
            ],
        },
        bridges=[
            (0, 0, "both", "auth I2C/SPI lockbox", "purple"),
            (1, 1, "both", "64-bit AKF FIFO", "green"),
            (2, 2, "lr", "ephemeral wrap", "teal"),
        ],
        boundary_label="Hardware Enclave Bus & Memory Protection Engine Boundary",
        footer="Even full sepOS code execution cannot read raw UID fuse bits to perform offline GPU passcode brute-forcing.",
    )


def gen_04_sptm_frame_retyping():
    build_fan_bands(
        P("04-extra-sptm-frame-retyping.svg"),
        "SPTM (GL2) Physical Frame Type Table & Deterministic sptm_retype() Invariants",
        [
            [
                {
                    "id": "sptm",
                    "tag": "Guarded Execution GL2 Root Monitor (osfmk/arm64/sptm/)",
                    "title": "Secure Page Table Monitor (SPTM) & Authoritative Frame Type Table",
                    "body": "Entered via lateral GENTER (0x00201420) or HCR_EL2-trapped SVC/HVC; sole entity permitted by SPRR to write page tables & IOMMU roots",
                    "theme": "slate",
                }
            ],
            [
                {
                    "id": "xnu_def",
                    "tag": "Frame Type · Kernel RW",
                    "title": "XNU_DEFAULT",
                    "body": "Standard writable XNU heap/stacks (PXN=1, UXN=1); permanently barred from executable mappings while writable",
                    "theme": "white",
                },
                {
                    "id": "xnu_pt",
                    "tag": "Frame Type · Translation",
                    "title": "XNU_PAGE_TABLE & IOMMU",
                    "body": "CPU L0-L3 PTE frames and AppleDART stream tables; mapped read-only to EL1 XNU, mutated solely via SPTM gates",
                    "theme": "amber",
                },
                {
                    "id": "user_exec",
                    "tag": "Frame Type · Verified Code",
                    "title": "XNU_USER_EXEC / JIT",
                    "body": "Immutable user text pages (or APRR-toggled BrowserEngineKit JIT); requires TXM (GL0) CDHash approval before X mapping",
                    "theme": "purple",
                },
                {
                    "id": "excl_sk",
                    "tag": "Frame Type · Exclave Domain",
                    "title": "SK_DOMAIN & ExclaveKit",
                    "body": "Isolated GL1 Secure Kernel (cL4) & GL0 conclave/EIC privacy-ledger frames unreachable by XNU virtual mappings",
                    "theme": "green",
                },
            ],
            [
                {
                    "id": "retype",
                    "tag": "Atomic Retyping Preconditions Enforced Before Any Type Transition",
                    "title": "sptm_retype(paddr, old_type, new_type) Requires Zero Active Aliases, Zero In-Flight Ops, & TLB Shootdown",
                    "body": "Blocks PTE corruption even under arbitrary EL1 R/W; bypassed only by unmodeled SoC MMIO DMA (CVE-2023-38606) or GPU residue",
                    "theme": "teal",
                }
            ],
        ],
        [
            ("sptm", "xnu_def", "owns type", "slate", False),
            ("sptm", "xnu_pt", "writes PTEs", "amber", False),
            ("sptm", "user_exec", "TXM GL0 gate", "purple", False),
            ("sptm", "excl_sk", "xnuproxy fence", "green", False),
            ("xnu_def", "retype", "unmap all", "teal", False),
            ("xnu_pt", "retype", "refcnt == 0", "teal", False),
            ("user_exec", "retype", "scrub / verify", "teal", False),
            ("excl_sk", "retype", "domain lock", "teal", False),
        ],
        footer="Every physical RAM frame belongs to exactly one SPTM type at any instant; XNU cannot alias writable data as executable code.",
    )


def gen_05_dsc_pac_slide_pointers():
    build_vertical_flow(
        P("05-extra-dsc-pac-slide-pointers.svg"),
        "dyld_shared_cache Slide Info v3/v5 & Kernel Page-In PAC Pointer Rebasing",
        [
            {
                "tag": "Sealed On-Disk Shared Cache (SSV or OS Cryptex1)",
                "title": "dyld_cache_mapping_and_slide_info & dyld_cache_slide_info5",
                "body": "Encodes 16 KB page_starts[pageIndex] delta chains (0xFFFF = NO_REBASE) across __DATA_CONST, __AUTH_CONST, and __AUTH_GOT",
                "theme": "slate",
            },
            {
                "tag": "64-Bit On-Disk Chained Fixup Encoding (fixup-chains.h)",
                "title": "dyld_chained_ptr_arm64e_shared_cache_rebase vs. _auth_rebase",
                "body": "Plain: {runtimeOffset:34, high8:8, next:11, auth:0} · Auth: {runtimeOffset:34, diversity:16, addrDiv:1, keyIsData:1, next:11, auth:1}",
                "theme": "purple",
                "edge_label": "faults 16 KB DATA page",
                "edge_color": "#5c4282",
            },
            {
                "tag": "XNU Kernel Page-In Handler (vm_shared_region_slide_page)",
                "title": "Single-Boot ASLR Slide Addition + In-Kernel QARMA PAC Signing",
                "body": "Walks next*8 chain in private kernel buffer, computes value_add + runtimeOffset + boot_slide, and signs auth=1 slots with IA/DA key + diversity",
                "theme": "teal",
                "edge_label": "walk delta != 0",
                "edge_color": "#236b66",
            },
            {
                "tag": "User-Space EL0 Hardware Protection (APRR / SPRR TPRO)",
                "title": "Read-Only TPRO Sealing of __DATA_CONST & PrebuiltLoader RuntimeState",
                "body": "Mapped clean/immutable into task; thread flips TPRO RW- only inside dyld fixup gates, then locks R-- prior to initializers",
                "theme": "green",
                "edge_label": "maps into task_t",
                "edge_color": "#2b6a4c",
            },
        ],
        side_notes={
            2: {
                "tag": "Anti-Oracle Invariant",
                "title": "Why Kernel Slides on Fault",
                "body": "Disk holds zero valid PAC tags; XNU signs pointers on page-in so shared pages stay clean across processes",
                "theme": "amber",
                "edge_label": "zero disk PACs",
                "edge_color": "#b07926",
                "dashed": True,
            },
            3: {
                "tag": "In-the-Wild Bypass",
                "title": "CVE-2026-20700 (DarkSword)",
                "body": "Corrupted dyld transition state during writable window to hijack legitimate PAC signing & _ModInitFuncs",
                "theme": "red",
                "edge_label": "state race",
                "edge_color": "#8d2d3b",
                "dashed": True,
            },
        },
        footer="Combining SSV disk immutability, kernel page-in PAC rebasing, and TPRO leaves only transient dyld state transitions exposed.",
    )


def main():
    os.makedirs(DIAG_DIR, exist_ok=True)
    gen_01_image4_der_tree()
    gen_02_localpolicy_hash_chain()
    gen_03_sks_keybag_uid_kdf()
    gen_04_sptm_frame_retyping()
    gen_05_dsc_pac_slide_pointers()
    print("SUCCESS: Generated and 7-way collision-verified all 5 Batch 1 extra SVG diagrams.")


if __name__ == "__main__":
    main()
