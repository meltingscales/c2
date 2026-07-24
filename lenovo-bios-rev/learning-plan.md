# BIOS Flashing / Reversing Learning Plan

## Reference material in this repo
- `gq0uk4.py` / `gq0uk4.txt` — third-party writeup + script for HP 15-dw1036ne (BIOS F.68, Insyde H2O, Compal ODM board 85F2). Three findings: RSA-2048 DXE-FV signature bypass, 55 hidden Setup fields (SuppressIf/GrayOutIf flip), Advanced/Power/Debug/Boot tab unlock. Used as a template for method, not assumed to apply directly to the target board.

## Goal
Write my own from-scratch BIOS mod script (not reuse the reference script's offsets) — find fingerprints/offsets myself via reverse engineering, the same way the reference author did.

## Target hardware
- Candidate: HP 15-dw1033dx (eBay, "for parts", $69.97, powers on, bad battery only) — same dw10xx family as the reference model (15-dw1036ne) but **not confirmed same BIOS version**. Model mismatch is fine since offsets will be found independently rather than reused.
- No assumption should be made that reference script offsets apply — different BIOS build likely has different fingerprints even on a related board.

## Hardware kit
- CH341A + SOIC8 test clip — primary flasher/dumper, in transit.
- Raspberry Pi 5 (4GB) + SOIC8-to-DIP clip adapter — secondary flasher via `flashrom -p linux_spi` over GPIO SPI. Note: Pi 5 GPIO pinout for flashrom differs from Pi 4, confirm current flashrom docs before wiring. Native 3.3V GPIO, no level shifter needed for typical SOIC8 flash parts.
- Plan: dump the same chip with both CH341A and Pi5/flashrom, diff the two dumps to confirm a clean read before doing anything else. Keep the first known-good dump untouched as the recovery/reference copy.

## Reverse-engineering workflow (modeled on the reference writeup)
1. **UEFIExtract/UEFITool** — unpack the dump into firmware volumes/modules.
2. **Ghidra** (optionally with GhidrAssistMCP) — locate the signature-check routine, tab-visibility blocklist, and Setup IFR suppress/gray-out gates. Note: verifier modules may be LZMA-compressed inside the image and invisible to a raw byte scan — decompress FVs before searching.
3. **Unicorn Engine + Capstone** — emulate any found check function standalone (outside real firmware) against known-good and known-bad inputs before touching real hardware.
4. **`cryptography` (Python)** — generate valid test signatures so the emulated verify path is exercised against real crypto, not fabricated data.
5. **CH341A / Pi5+flashrom** — flash the physical chip, keep the pristine dump on hand for recovery if a patch bricks the board.

## Safety notes
- Confirm no Intel Boot Guard is present (check FIT: Startup ACM / Key Manifest / Boot Policy Manifest) before assuming a PEI-phase patch will survive reboot — this was the reference board's justification for why patching an unsigned early-boot module worked.
- Always keep an unmodified dump before any patching.
- Physical recovery flasher (CH341A or Pi5) is the safety net for any bad flash — don't patch without one on hand and tested working first.
