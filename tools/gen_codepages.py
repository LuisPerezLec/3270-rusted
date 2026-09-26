#!/usr/bin/env python3
"""Generate src/ebcdic/tables.rs from Python's own EBCDIC codecs.

The tables are data, not craft: generating them removes any chance of a
transcription slip, and keeps the file reproducible.

    python3 tools/gen_codepages.py > src/ebcdic/tables.rs

Adding a code page is a one-line change to PAGES, provided Python ships the
codec. Code pages Python lacks (cp1047, cp277 and friends) would need their
tables supplied from the IBM mappings.
"""
import sys

PAGES = ["cp037", "cp273", "cp500", "cp1026", "cp1140"]
DESC = {
    "cp037": "USA, Canada, Netherlands, Portugal, Brazil, Australia, New Zealand",
    "cp273": "Germany, Austria",
    "cp500": "International #5 (Belgium, Switzerland)",
    "cp1026": "Turkey",
    "cp1140": "as cp037, with the euro sign at 0x9F",
}

# Decode every page first, so the header can import UNDEF only if it is used.
decoded = {}
has_holes = False
for page in PAGES:
    row = []
    for i in range(256):
        try:
            row.append(ord(bytes([i]).decode(page)))
        except UnicodeDecodeError:
            row.append(None)
            has_holes = True
    decoded[page] = row

out = sys.stdout
out.write('''//! Generated code page tables. Do not edit by hand.
//!
//! Regenerate with `python3 tools/gen_codepages.py > src/ebcdic/tables.rs`.
//!
//! `#[rustfmt::skip]` keeps the generator's layout stable, so regenerating does
//! not fight `cargo fmt`.

''')
out.write("use super::CodePage;\n")
if has_holes:
    out.write("use super::UNDEF;\n")
out.write("\n")

consts = []
for page in PAGES:
    dec = decoded[page]
    ident = page.upper()
    consts.append(ident)
    out.write(f"/// {page} — {DESC[page]}.\n")
    out.write(f"pub const {ident}: CodePage = CodePage {{\n")
    out.write(f'    name: "{page}",\n')
    out.write(f'    description: "{DESC[page]}",\n')
    out.write(f"    decode: &{ident}_DECODE,\n")
    out.write(f"    encode: &{ident}_ENCODE,\n")
    out.write("};\n\n")

    out.write("#[rustfmt::skip]\n")
    out.write(f"static {ident}_DECODE: [u16; 256] = [\n")
    for row in range(0, 256, 8):
        cells = ", ".join("UNDEF" if c is None else f"0x{c:04X}"
                          for c in dec[row:row + 8])
        out.write(f"    {cells},\n")
    out.write("];\n\n")

    rev = sorted((cp, i) for i, cp in enumerate(dec) if cp is not None)
    out.write("#[rustfmt::skip]\n")
    out.write(f"static {ident}_ENCODE: [(u16, u8); {len(rev)}] = [\n")
    for row in range(0, len(rev), 6):
        cells = ", ".join(f"(0x{c:04X}, 0x{b:02X})" for c, b in rev[row:row + 6])
        out.write(f"    {cells},\n")
    out.write("];\n\n")

out.write("/// Every code page compiled in.\n")
out.write("pub(super) static ALL: &[CodePage] = &[" + ", ".join(consts) + "];\n\n")
out.write("/// The code page assumed when a host does not say otherwise.\n")
out.write("pub const DEFAULT: CodePage = CP037;\n")
