#!/usr/bin/env python3
"""
https://www.reddit.com/r/ClaudeAI/comments/1v1vwg7/claude_code_unlocked_my_laptops_bios/

hp_15dw1036ne_bios_unlock.py — one-file, from-scratch BIOS mod for the
HP 15-dw1036ne (Insyde H2O firmware, BIOS F.68, Compal ODM board 85F2).

Takes your own stock dump of this exact BIOS version and reproduces, byte
for byte, a firmware image that has been flashed and tested on real hardware
three separate times. It combines three independent findings from a long
reverse-engineering session:

  1. RSA-2048 DXE-FV signature-check bypass ("H19SignCheckPei" crack)
  2. 55 hidden BIOS-Setup fields unhidden (SuppressIf/GrayOutIf gate flip)
  3. Advanced/Power/Debug/Boot made literal top-level Setup tabs
     (FormBrowser.efi tab-visibility blocklist neutered)

Nothing here is a generic "how to hack any BIOS" tool. Every offset and
byte fingerprint below is specific to this exact firmware build and was
found by reverse engineering it from scratch (Ghidra + raw disassembly +
brute-force byte scanning) over many sessions. If you have a different
board or BIOS version, none of the offsets will match and the script will
refuse to proceed (see the assertions throughout) rather than silently
doing the wrong thing to your firmware.

This script does NOT embed or redistribute any of HP/Insyde/Compal's
firmware code — only small (8-128 byte) byte-level fingerprints used to
*locate* code in YOUR OWN dump, the same way a virus scanner signature
does. You provide the actual firmware (your own legally-owned dump); this
script only tells it where to look and what single bytes to flip.

======================================================================
PART 1 — RSA-2048 DXE-FV SIGNATURE CHECK BYPASS
======================================================================

HP/Compal sign the whole compressed DXE firmware volume with a detached
RSA-2048 signature, checked by a PEI-phase module named H19SignCheckPei
before the DXE volume is trusted. Touch a single byte in that volume
without this bypass and stock firmware shows a "BIOS corruption has been
detected" screen and refuses to boot.

H19SignCheckPei is itself LZMA-compressed (invisible to a raw byte scan
of the flash image — it only exists post-decompression), and exists in
2-3 copies (primary + backup boot-block group). Its verify function ends
with an unmistakable tail, present in both the SHA-256 and SHA-1 code
paths observed:

    CALL  RsaVerifyCore     ; does the actual RSA-2048 public-key math
    TEST  AL, AL
    JNZ   ok                ; verify passed -> skip the failure path
    MOV   EBX, 0x8000001a   ; verify FAILED
  ok:
    RET

Byte fingerprint of that tail: 84 C0 75 05 BB 1A 00 00 80
The patch is one byte: flip the JNZ (0x75) to JMP (0xEB), so the function
returns SUCCESS unconditionally regardless of what the RSA math actually
decided. No key material needed, nothing is forged — the firmware simply
stops caring about the signature.

This script finds every LZMA-compressed EFI_GUID_DEFINED section in the
image (recursively, since compressed volumes nest inside each other),
decompresses each one, patches every fingerprint match found, and
recompresses+splices the result back into the EXACT original byte range
(zero-padded). File and section sizes never change, so no FV/FFS layout
shifts and no checksums need recomputing on this particular image.

No Intel Boot Guard was found on this board (checked via the flash's FIT:
no Startup ACM / Key Manifest / Boot Policy Manifest) — that absence is
*why* patching this unsigned, PEI-phase boot-block module survives a
reboot. If you're trying this on a different board, check your own FIT
before trusting any of this.

======================================================================
PART 2 — 55 HIDDEN SETUP FIELDS (SuppressIf / GrayOutIf CONSTANT FLIP)
======================================================================

The Setup UI is built from IFR (Internal Forms Representation) opcodes
compiled into SetupUtility.efi. Many real, functional fields (AHCI Option
ROM, PRMRR size, SATA port config, BIOS Guard, assorted CPU/thermal
fields, etc.) are present and fully wired up, but wrapped in:

    SuppressIf { True }   -> field is always hidden
    GrayOutIf { True }    -> field is always read-only

as opcode bytes `0A 82 46 02` and `19 82 46 02` respectively (the `46` is
the literal boolean constant TRUE in IFR encoding). Flipping that one
byte to `47` (FALSE) makes SuppressIf always show the field and GrayOutIf
always leave it editable — no other change needed, because these are
constant conditions, not conditions on real hardware/CPU state.

There are exactly 27 SuppressIf{True} and 28 GrayOutIf{True} occurrences
inside SetupUtility's IFR data on this firmware build (55 total). The
script asserts these exact counts before and after patching, so it will
refuse to run rather than silently patch the wrong thing if your build
differs even slightly.

======================================================================
PART 3 — LITERAL Advanced / Power / Debug / Boot TOP-LEVEL TABS
======================================================================

This was the hard one. ~20 prior attempts across many sessions targeted
SetupUtility.efi and SCU_dispatch.efi metadata (ClassGuid, Tiano SubClass,
IFR-level SuppressIf gates) — all hardware-tested dead ends, because the
real mechanism lives somewhere else entirely: **FormBrowser.efi**, the
actual UI driver that builds the visible tab strip (SetupUtility only
publishes formsets into the HII database; it doesn't decide what's shown).

Inside FormBrowser.efi there's a small function (named here
`IsHiddenFormset_4GuidCheck`) that builds, via stack-immediate `mov`
instructions (invisible to a plain GUID-blob byte search — found instead
by scanning for each GUID's 4-byte Data1 field as a code immediate), a
hardcoded 4-entry blocklist:

    Boot      2D068309-...
    Advanced  C6D4769E-...
    Power     A6712873-...
    Debug     A6E38A2F-...

Formsets NOT on this list are kept immediately. Blocklisted ones require
an extra call through a shared OEM protocol slot (ctx+0x373) that
empirically always fails on this hardware, causing exclusion. The calling
function (`TabFilterCaller`) has one JZ instruction gating that fallible
extra check:

    TEST AL, AL
    JZ   +0x17    ; branch away = EXCLUDE this formset from the tab strip
    ...

One byte, JZ (0x74) -> JMP (0xEB), makes it always take the "keep" path
regardless of what that fallible protocol call returns. Flashed and
confirmed on real hardware: Advanced, Power, Debug, and the internal
"Boot" formset all appear as literal top-level tabs. Zero regressions to
Main/Security/Boot Options/Configuration/Exit, to any setting, or to
normal boot.

======================================================================
USAGE
======================================================================

    python3 hp_15dw1036ne_bios_unlock.py original1.bin -o unlocked.bin

Input must be your own 16MB stock dump of BIOS F.68 for this board. The
script will tell you exactly which assertion failed if anything about
your dump doesn't match what this was built against. Every patch is
re-verified against the finished output (gate counts, byte-level checks)
before the script reports success.

======================================================================
SAFETY / RECOVERY — READ THIS BEFORE FLASHING ANYTHING
======================================================================

  * ALWAYS keep your original stock dump. This script never overwrites
    your input file.
  * ALWAYS have a way to reflash externally (CH341A + SOIC-8 clip) before
    you flash anything you didn't get from HP. Don't rely on any in-system
    recovery path — part of what Part 1 disables IS signature-driven
    recovery logic.
  * This was flash-tested on ONE board model (HP 15-dw1036ne, F.68,
    Compal 85F2) with NO Intel Boot Guard present. If you're on a
    different board or a board with Boot Guard enforced, do not assume
    any of this applies — verify your own FIT first.
  * This is a hobbyist reverse-engineering project on the author's own
    hardware, published for education/community reference. You are
    responsible for what you flash to your own device.
"""

import argparse
import lzma
import struct
import sys

# ======================================================================
# Shared LZMA / EFI_GUID_DEFINED-section plumbing
# ======================================================================

EE_GUID_LE = bytes.fromhex("98584eee143959429d6edc7bd79403cf")
# EE4E5898-3914-4259-9D6E-DC7BD79403CF, the standard EDK2 LZMA custom
# decompress GUID, as stored little-endian in a section header.

LZMA_FILTERS = [
    {"id": lzma.FILTER_LZMA1, "dict_size": 1 << 24, "lc": 3, "lp": 0, "pb": 0,
     "mode": lzma.MODE_NORMAL, "nice_len": 128, "mf": lzma.MF_BT4, "depth": 0},
]


def rd24(buf, p):
    return buf[p] | (buf[p + 1] << 8) | (buf[p + 2] << 16)


def find_ee_sections(buf):
    """Scan buf for EFI_GUID_DEFINED_SECTION headers wrapping the LZMA
    custom decompress GUID. Returns [(header_start, section_size, data_offset), ...]."""
    out = []
    i = 0
    n = len(buf)
    while True:
        i = buf.find(EE_GUID_LE, i)
        if i < 0:
            break
        hdr = i - 4  # section header: 3B size, 1B type=0x02, then 16B GUID at +4
        if hdr >= 0 and buf[hdr + 3] == 0x02:
            ssize = rd24(buf, hdr)
            if 0x18 <= ssize <= n - hdr:
                dataoff = struct.unpack_from("<H", buf, hdr + 0x14)[0]
                if 0x14 <= dataoff < ssize:
                    out.append((hdr, ssize, dataoff))
        i += 1
    return out


def lzma_alone_decompress(payload):
    return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE).decompress(payload)


def lzma_alone_compress(data):
    c = bytearray(lzma.compress(bytes(data), format=lzma.FORMAT_ALONE, filters=LZMA_FILTERS))
    c[5:13] = struct.pack("<Q", len(data))  # EDK2 needs the true uncompressed size here
    c = bytes(c)
    assert lzma_alone_decompress(c) == bytes(data), "recompression round-trip failed"
    return c


# ======================================================================
# PART 1 — RSA-2048 DXE-FV signature-check bypass (H19SignCheckPei)
# ======================================================================

RSA_FINGERPRINT = bytes.fromhex("84c07505bb1a000080")
# 84 C0 75 05 BB 1A 00 00 80 = TEST AL,AL / JNZ +5 / MOV EBX,0x8000001a
RSA_JNZ_OFFSET_IN_FINGERPRINT = 2


class RsaCrackReport:
    def __init__(self):
        self.patched_sites = []
        self.lzma_seen = 0
        self.lzma_patched = 0
        self.lzma_too_big = []


def patch_rsa_fingerprint(buf):
    b = bytearray(buf)
    count = 0
    i = 0
    while True:
        i = bytes(b).find(RSA_FINGERPRINT, i)
        if i < 0:
            break
        jnz_pos = i + RSA_JNZ_OFFSET_IN_FINGERPRINT
        if b[jnz_pos] == 0x75:
            b[jnz_pos] = 0xEB
            count += 1
        i += 1
    return bytes(b), count


def rsa_crack_recursive(buf, report, depth=0):
    """Recursively patch buf (bytes). Returns (new_buf, changed: bool)."""
    changed = False

    buf, direct_count = patch_rsa_fingerprint(buf)
    if direct_count:
        changed = True
        report.patched_sites.append({"depth": depth, "kind": "direct", "count": direct_count})

    buf = bytearray(buf)
    for hdr, ssize, dataoff in find_ee_sections(bytes(buf)):
        report.lzma_seen += 1
        payload_start = hdr + dataoff
        payload_len = ssize - dataoff
        payload = bytes(buf[payload_start:payload_start + payload_len])
        try:
            dec = lzma_alone_decompress(payload)
        except Exception:
            continue

        new_dec, sub_changed = rsa_crack_recursive(dec, report, depth + 1)

        if sub_changed:
            new_payload = lzma_alone_compress(new_dec)
            if len(new_payload) <= payload_len:
                buf[payload_start:payload_start + payload_len] = (
                    new_payload + b"\x00" * (payload_len - len(new_payload))
                )
                report.lzma_patched += 1
                changed = True
            else:
                report.lzma_too_big.append({
                    "depth": depth + 1, "offset": payload_start,
                    "needed": len(new_payload), "budget": payload_len,
                })

    return bytes(buf), changed


def apply_rsa_crack(img: bytearray) -> bytearray:
    report = RsaCrackReport()
    patched, changed = rsa_crack_recursive(bytes(img), report)
    assert changed, "RSA crack made no changes -- different firmware build?"
    total_sites = sum(site["count"] for site in report.patched_sites)
    assert total_sites == 6, f"expected six RSA patch sites, got {total_sites}"
    assert report.lzma_patched == 4, (
        f"expected four recursively patched LZMA sections, got {report.lzma_patched}"
    )
    print(f"  [1] RSA verifier crack: {total_sites}/6 sites patched, "
          f"{report.lzma_patched} LZMA sections recompressed+spliced")
    return bytearray(patched)


# ======================================================================
# PART 2 + 3 fingerprints (SetupUtility IFR region, FormBrowser tab patch)
# ======================================================================

# 64-byte code fingerprint taken from local offset 0x1000 inside the
# SetupUtility.efi PE image -- used only to locate that module's region
# inside the decompressed DXE FV. SETUP_LEN is that module's total size,
# used to bound how far the IFR-gate scan is allowed to look.
SETUP_SIG = bytes.fromhex(
    "921500488d0d5a651b00e845990000488944243848837c2438007441488b44"
    "243848894424204c8b4c244841b807000000488d15d48f1500488d0d45651b"
    "0048"
)
SETUP_LEN = 0x1C1504

# 128-byte code fingerprint at local offset 0x400 inside FormBrowser.efi,
# used to locate that module inside the decompressed DXE FV.
FORMBROWSER_ANCHOR_OFF = 0x400
FORMBROWSER_ANCHOR = bytes.fromhex(
    "442440488d0d62ffffff48894858488bd3488bcfe8fb000000488bf04885c0"
    "790b488bd3488bcfe8a8000000488bc6488b5c2430488b7424384883c4205f"
    "c3cc48895c2408574883ec20488bda488bf9e8cf8d0200488bd3488bcfe8d4"
    "8d0200488bd3488bcfe889920200488bd3488bcfe89a940200488bd3488bcf"
    "e8939502"
)

# The one-byte tab-filter patch, local to FormBrowser.efi. TAB_WINDOW is
# "TEST AL,AL / J?? +0x17 / MOV RAX,[RBP+0x58]" with the JZ/JMP opcode
# byte (index 2) as the one thing that changes between stock and patched.
TAB_PATCH_OFF = 0x173CE
TAB_OLD_WINDOW_OFF = 0x173CC
TAB_WINDOW_PREFIX = bytes.fromhex("84c0")       # TEST AL,AL
TAB_WINDOW_SUFFIX = bytes.fromhex("17488b4558")  # +0x17 / MOV RAX,[RBP+0x58]
TAB_OLD_BYTE = 0x74  # JZ short
TAB_NEW_BYTE = 0xEB  # JMP short (same length, same displacement byte kept)


def locate_fv(img: bytes):
    """Find the decompressed Setup DXE firmware volume by looking for the
    SetupUtility signature inside every LZMA-compressed EE section."""
    for header, section_size, data_offset in find_ee_sections(img):
        try:
            dec = lzma_alone_decompress(
                bytes(img[header + data_offset: header + section_size])
            )
        except Exception:
            continue
        if len(dec) > 0x1000000 and dec.find(SETUP_SIG) >= 0:
            return header, section_size, data_offset, bytearray(dec)
    raise SystemExit(
        "Setup DXE FV not found -- this doesn't look like the expected "
        "HP 15-dw1036ne F.68 image (SETUP_SIG fingerprint not found anywhere)."
    )


def locate_setuputility(fv: bytes) -> tuple[int, int]:
    match = fv.find(SETUP_SIG)
    assert match >= 0, "SetupUtility signature not found"
    su_base = match - 0x1000
    su_end = su_base + SETUP_LEN
    return su_base, su_end


def locate_formbrowser(fv: bytes, expected_patch_byte: int) -> int:
    matches = []
    pos = fv.find(FORMBROWSER_ANCHOR)
    while pos >= 0:
        base = pos - FORMBROWSER_ANCHOR_OFF
        prefix_off = base + TAB_OLD_WINDOW_OFF
        patch_off = base + TAB_PATCH_OFF
        suffix_off = patch_off + 1
        if (base >= 0
                and fv[prefix_off:patch_off] == TAB_WINDOW_PREFIX
                and fv[patch_off] == expected_patch_byte
                and fv[suffix_off:suffix_off + len(TAB_WINDOW_SUFFIX)] == TAB_WINDOW_SUFFIX):
            matches.append(base)
        pos = fv.find(FORMBROWSER_ANCHOR, pos + 1)
    assert len(matches) == 1, (
        f"expected exactly one FormBrowser.efi match, got {len(matches)} -- "
        "different firmware build?"
    )
    return matches[0]


def flip_ifr_gates(fv: bytearray, su_base: int, su_end: int) -> tuple[int, int]:
    def flip(pat: bytes, name: str) -> int:
        n = 0
        i = su_base
        while True:
            j = fv.find(pat, i, su_end)
            if j < 0:
                break
            assert fv[j + 2] == 0x46, f"unexpected byte at {hex(j)}"
            fv[j + 2] = 0x47  # True(0x46) -> False(0x47)
            n += 1
            i = j + 1
        print(f"      flipped {name}: {n}")
        return n

    n1 = flip(b"\x0a\x82\x46\x02", "SuppressIf{True}")  # expect 27
    n2 = flip(b"\x19\x82\x46\x02", "GrayOutIf{True}")   # expect 28
    return n1, n2


def patch_tab_filter(fv: bytearray, fb_base: int) -> None:
    absolute = fb_base + TAB_PATCH_OFF
    assert fv[absolute] == TAB_OLD_BYTE, f"unexpected byte at {hex(absolute)}"
    fv[absolute] = TAB_NEW_BYTE
    print(f"  [3] FormBrowser.efi base={fb_base:#x}; one-byte JZ->JMP applied "
          f"(local {TAB_PATCH_OFF:#x}: {TAB_OLD_BYTE:#x} -> {TAB_NEW_BYTE:#x})")


def splice_fv(img: bytearray, header: int, section_size: int,
              data_offset: int, fv: bytearray) -> None:
    recompressed = lzma_alone_compress(fv)
    budget = section_size - data_offset
    assert len(recompressed) <= budget, "recompressed payload exceeds section budget"
    region = bytearray(b"\x00" * budget)
    region[:len(recompressed)] = recompressed
    img[header + data_offset:header + section_size] = region
    print(f"      recompressed {len(recompressed):#x} / budget {budget:#x} "
          f"(slack {budget - len(recompressed):#x})")


def validate_finished_rom(result: bytes) -> None:
    """Re-extract the written-form ROM and verify all patches landed byte-for-byte."""
    _header, _section_size, _data_offset, fv = locate_fv(result)

    su_base, su_end = locate_setuputility(fv)
    n_true_left = fv.count(b"\x0a\x82\x46\x02", su_base, su_end) \
        + fv.count(b"\x19\x82\x46\x02", su_base, su_end)
    n_false = fv.count(b"\x0a\x82\x47\x02", su_base, su_end) \
        + fv.count(b"\x19\x82\x47\x02", su_base, su_end)
    assert n_true_left == 0, f"{n_true_left} True-gates remain in finished ROM"
    assert n_false == 55, f"expected 55 False-gates in finished ROM, found {n_false}"
    print(f"  [verify] finished ROM: 0 True-gates left / {n_false} False-gates confirmed")

    fb_base = locate_formbrowser(fv, TAB_NEW_BYTE)
    assert fv[fb_base + TAB_PATCH_OFF] == TAB_NEW_BYTE
    print("  [verify] finished ROM: FormBrowser tab-filter patch confirmed")


# ======================================================================
# Driver
# ======================================================================

def build(src_path: str, out_path: str) -> bytes:
    img = bytearray(open(src_path, "rb").read())
    assert len(img) == 16 * 1024 * 1024, f"expected a 16MB image, got {len(img)} bytes"

    header, section_size, data_offset, fv = locate_fv(bytes(img))
    original_fv = bytes(fv)

    su_base, su_end = locate_setuputility(fv)
    print(f"DXE FV @{header:#x}  decompressed={len(fv):#x}  "
          f"su_base={su_base:#x} su_end={su_end:#x}")

    print("  [2] flipping SetupUtility IFR gates...")
    n1, n2 = flip_ifr_gates(fv, su_base, su_end)
    assert (n1, n2) == (27, 28), f"gate count changed: {(n1, n2)} (expected 27,28)"

    fb_base = locate_formbrowser(fv, TAB_OLD_BYTE)
    patch_tab_filter(fv, fb_base)

    fv_diff = [i for i, (a, b) in enumerate(zip(original_fv, fv)) if a != b]
    expected_diff_count = 55 + 1
    assert len(fv_diff) == expected_diff_count, (
        f"expected {expected_diff_count} changed bytes in decompressed FV, got {len(fv_diff)}"
    )
    assert all(su_base <= i < su_end for i in fv_diff if i != fb_base + TAB_PATCH_OFF)
    assert (fb_base + TAB_PATCH_OFF) in fv_diff
    print(f"  decompressed FV diff: {len(fv_diff)} bytes "
          f"(55 in SetupUtility IFR data + 1 in FormBrowser code), no overlap")

    splice_fv(img, header, section_size, data_offset, fv)
    result = apply_rsa_crack(img)
    validate_finished_rom(bytes(result))

    with open(out_path, "wb") as f:
        f.write(result)

    print(f"\nOUT {out_path}")
    return bytes(result)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("input", help="path to your own stock HP 15-dw1036ne F.68 dump (16MB)")
    ap.add_argument("-o", "--output", default="unlocked.bin", help="output path (default: unlocked.bin)")
    args = ap.parse_args()
    build(args.input, args.output)


if __name__ == "__main__":
    main()
