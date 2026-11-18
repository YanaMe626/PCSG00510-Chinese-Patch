"""Extract PCSG00510 font, exact code-to-slot mapping, and LZSS script data.

Mapping: Ghidra FUN_8100d0b2 / FUN_8100dca8 / FUN_8100dfb8.
Decompression: Ghidra FUN_8104da28 (4096-byte zero ring, initial 0xFEE).
"""
from pathlib import Path
from collections import Counter, defaultdict
import csv
import hashlib
import json
import struct
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from elftools.elf.elffile import ELFFile

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "02_解包资源/PCSG00510_decrypted/data"
FONT = ROOT / "06_中文字体/original_font"
TEXT = ROOT / "04_日文原文"
REPORT = ROOT / "03_文件结构分析/ghidra"


def glyph_index(raw: bytes) -> int:
    lead = raw[0]
    if not (0x81 <= lead <= 0x9F or 0xE0 <= lead <= 0xFC):
        return lead + (0x2CF if lead < 0x80 else 0x2AD)
    if len(raw) != 2 or not (0x40 <= raw[1] <= 0xFC and raw[1] != 0x7F):
        raise ValueError("invalid Shift-JIS pair")
    row = (lead - (0x71 if lead < 0xA0 else 0xB1)) * 2
    trail = raw[1] - int(raw[1] > 0x7F)
    if trail > 0x9D:
        row += 2
        col = trail - 0x7D
    else:
        row += 1
        col = trail - 0x1F
    return (row - 0x21) * 94 + col - 0x21


def write_tsv(path, rows, fields):
    with path.open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fields, delimiter="\t", lineterminator="\n")
        w.writeheader()
        w.writerows(rows)


def extract_unicode_table():
    path = DATA.parent / "PCSG00510.elf"
    raw = path.read_bytes()
    with path.open("rb") as f:
        segments = list(ELFFile(f).iter_segments())
    va = 0x810B8A54
    segment = next(s for s in segments if s["p_type"] == "PT_LOAD" and s["p_vaddr"] <= va < s["p_vaddr"] + s["p_filesz"])
    offset = int(segment["p_offset"]) + va - int(segment["p_vaddr"])
    end = offset + 65536 * 2
    if end > int(segment["p_offset"]) + int(segment["p_filesz"]):
        raise ValueError("Unicode LUT extends beyond initialized ELF data")
    table = raw[offset:end]
    (FONT / "eboot_unicode_to_sjis.bin").write_bytes(table)
    rows = []
    inverse = defaultdict(list)
    for cp, code in enumerate(struct.unpack("<65536H", table)):
        if code == 0xFFFF:
            continue
        buf = code.to_bytes(2, "big") if code > 255 else bytes([code])
        inverse[buf.hex().upper()].append(cp)
        try:
            idx = glyph_index(buf)
        except ValueError:
            idx = -1
        ch = chr(cp)
        rows.append({"unicode": f"U+{cp:04X}", "character": ch if ch.isprintable() else "",
                     "code_hex": buf.hex().upper(), "glyph_index": idx,
                     "within_font": 0 <= idx < 8192,
                     "elf_file_offset": f"0x{offset+cp*2:X}"})
    write_tsv(FONT / "eboot_unicode_to_sjis.tsv", rows, list(rows[0]))
    return inverse, {"address": "0x810B8A54", "file_offset": f"0x{offset:X}",
                     "entries": 65536, "entry_size": 2, "endianness": "little", "unmapped_value": "FFFF",
                     "mapped_unicode_entries": len(rows), "mapped_entries_within_font": sum(r["within_font"] for r in rows),
                     "sha256": hashlib.sha256(table).hexdigest()}


def extract_font():
    FONT.mkdir(parents=True, exist_ok=True)
    unicode_aliases, unicode_info = extract_unicode_table()
    raw = (DATA / "font32.vtx").read_bytes()
    magic, fmt, w, h, *_ = struct.unpack_from("<8I", raw)
    if (magic, fmt, w, h, len(raw)) != (0x787476, 0x100, 2048, 4096, 0x402060):
        raise ValueError("Unexpected font header")
    palette = np.frombuffer(raw[0x20:0x60], np.uint8).reshape(16, 4)
    packed = np.frombuffer(raw[0x60:0x400060], np.uint8)
    unpacked = np.empty(len(packed) * 2, np.uint8)
    unpacked[0::2] = packed & 15
    unpacked[1::2] = packed >> 4
    cells = unpacked.reshape(8192, 32, 32)
    # The stored data consists of consecutive 32x32 cells (512 bytes each).
    atlas = cells.reshape(128, 64, 32, 32).transpose(0, 2, 1, 3).reshape(h, w)
    Image.fromarray(palette[atlas], "RGBA").save(FONT / "font32_atlas.png")
    Image.fromarray(atlas, "L").save(FONT / "font32_indices.png")
    flags = raw[0x400060:]
    (FONT / "font32_tail_flags.bin").write_bytes(flags)
    # Lossless verification includes palette, pixels, header, and opaque tail.
    restored_cells = atlas.reshape(128, 32, 64, 32).transpose(0, 2, 1, 3).reshape(-1)
    repacked = restored_cells[0::2] | (restored_cells[1::2] << 4)
    rebuilt = raw[:0x60] + repacked.tobytes() + flags
    if rebuilt != raw:
        raise AssertionError("Font byte roundtrip failed")
    aliases = defaultdict(list)
    rows = []
    codes = [bytes([c]) for c in range(0x20, 0x7F)] + [bytes([c]) for c in range(0xA1, 0xE0)]
    codes += [bytes([a, b]) for a in list(range(0x81, 0xA0)) + list(range(0xE0, 0xFD))
              for b in range(0x40, 0xFD) if b != 0x7F]
    for code in codes:
        index = glyph_index(code)
        if not 0 <= index < 8192:
            continue
        try:
            ch = code.decode("cp932")
        except UnicodeDecodeError:
            ch = ""
        if len(ch) > 1:
            ch = ""
        row = {"code_hex": code.hex().upper(), "character": ch,
               "unicode": f"U+{ord(ch):04X}" if ch else "", "glyph_index": index,
               "atlas_x": index % 64 * 32, "atlas_y": index // 64 * 32,
               "vtx_offset": f"0x{0x60 + index * 512:X}",
               "ink_pixels": int(np.count_nonzero(palette[cells[index], 3])),
               "tail_flag": flags[index], "unicode_source": "CP932" if ch else "unassigned",
               "eboot_unicode_aliases": ",".join(f"U+{cp:04X}" for cp in unicode_aliases[code.hex().upper()])}
        rows.append(row)
        aliases[index].append(row)
    write_tsv(FONT / "game_code_table.tsv", rows, list(rows[0]))
    slots = []
    for i in range(8192):
        candidates = aliases[i]
        named = [r for r in candidates if r["character"]]
        slots.append({"glyph_index": i, "atlas_x": i % 64 * 32, "atlas_y": i // 64 * 32,
                      "vtx_offset": f"0x{0x60 + i * 512:X}",
                      "code_aliases": ",".join(r["code_hex"] for r in candidates),
                      "characters": "|".join(dict.fromkeys(r["character"] for r in named)),
                      "ink_pixels": int(np.count_nonzero(palette[cells[i], 3])),
                      "tail_flag": flags[i]})
    write_tsv(FONT / "font_slots.tsv", slots, list(slots[0]))
    (FONT / "game_cp932.tbl").write_text(
        "\n".join(r["code_hex"] + "=" + r["character"] for r in rows if r["character"]) + "\n", encoding="utf-8")
    blank = [r for r in slots if not r["ink_pixels"]]
    write_tsv(FONT / "blank_slots.tsv", blank, list(slots[0]))
    labels = ["8140", "8141", "8142", "8160", "824F", "8260", "8281", "82A0", "82F1", "8341", "8393", "8740",
              "889F", "8ABF", "8E9A", "93FA", "967B", "8CEA", "41", "61", "30", "A6", "B1", "DF"]
    preview = Image.new("RGB", (768, 4 * 108), (31, 37, 47))
    draw = ImageDraw.Draw(preview)
    label_font = ImageFont.truetype("C:/Windows/Fonts/consola.ttf", 15)
    jp_font = ImageFont.truetype("C:/Windows/Fonts/msgothic.ttc", 16)
    for j, code in enumerate(labels):
        buf = bytes.fromhex(code)
        idx = glyph_index(buf)
        x, y = j % 6 * 128, j // 6 * 108
        cell = Image.fromarray(palette[cells[idx]], "RGBA").resize((64, 64), Image.Resampling.NEAREST)
        preview.paste(cell, (x + 32, y + 3), cell)
        try:
            char = buf.decode("cp932")
        except UnicodeDecodeError:
            char = "?"
        draw.text((x + 8, y + 69), code + " " + char, font=jp_font, fill=(238, 238, 238))
        draw.text((x + 8, y + 89), "slot " + str(idx), font=label_font, fill=(160, 180, 200))
    preview.save(FONT / "font_preview.png")
    info = {"source_sha256": hashlib.sha256(raw).hexdigest(), "width": w, "height": h,
            "vtx_kind_byte": raw[4], "little_endian_header_flag": raw[5], "vtx_loader_function": "0x810158F4",
            "cell_width": 32, "cell_height": 32, "slots": 8192, "pixel_offset": "0x60",
            "bytes_per_glyph": 512, "palette": palette.tolist(), "tail_offset": "0x400060",
            "tail_size": len(flags), "tail_value_counts": dict(Counter(flags)),
            "tail_semantics": "unknown; preserved verbatim", "pixel_layout": "consecutive 32x32 cells, low nibble first",
            "code_rows": len(rows), "cp932_rows": sum(bool(r["character"]) for r in rows),
            "blank_slots": len(blank), "font_byte_roundtrip": True,
            "mapping_functions": ["0x8100D0B2", "0x8100DCA8", "0x8100DFB8"],
            "unicode_lut": unicode_info,
            "unicode_note": "Code-to-slot mapping is from code; Unicode names use CP932, custom/unassigned glyphs require visual review."}
    (FONT / "font_report.json").write_text(json.dumps(info, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    return info


def decompress_lzss(src: bytes):
    size = struct.unpack_from("<I", src)[0]
    ring = bytearray(4096)
    rpos = 0xFEE
    pos = 4
    out = bytearray()
    flags = 0
    while len(out) < size:
        if not flags & 0x100:
            if pos >= len(src):
                raise ValueError("truncated LZSS flag")
            flags = src[pos] | 0xFF00
            pos += 1
        if flags & 1:
            if pos >= len(src):
                raise ValueError("truncated literal")
            values = [src[pos]]
            pos += 1
            for value in values:
                out.append(value)
                ring[rpos] = value
                rpos = (rpos + 1) & 4095
        else:
            if pos + 2 > len(src):
                raise ValueError("truncated match")
            low, high = src[pos:pos + 2]
            pos += 2
            offset = low | (high & 0xF0) << 4
            length = (high & 15) + 3
            for j in range(length):
                value = ring[(offset + j) & 4095]
                out.append(value)
                ring[rpos] = value
                rpos = (rpos + 1) & 4095
                if len(out) == size:
                    break
        flags >>= 1
    return bytes(out), pos


def main():
    TEXT.mkdir(parents=True, exist_ok=True)
    REPORT.mkdir(parents=True, exist_ok=True)
    info = extract_font()
    src = (DATA / "sn.bin").read_bytes()
    data, consumed = decompress_lzss(src)
    (TEXT / "sn_decompressed.bin").write_bytes(data)
    report = {"compressed_size": len(src), "decompressed_size": len(data), "consumed_bytes": consumed,
              "trailing_bytes": len(src) - consumed, "sha256": hashlib.sha256(data).hexdigest(),
              "function": "0x8104DA28"}
    (REPORT / "script_decompress_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"font": info, "script": report}, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
