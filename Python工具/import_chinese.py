"""Build the PCSG00510 Chinese font, scenario and Vita3K executable."""

import argparse
import csv
import hashlib
import json
import os
import re
from collections import defaultdict
from pathlib import Path
from struct import pack_into, unpack_from

import numpy as np
from fontTools.ttLib import TTFont
from PIL import Image, ImageDraw, ImageFilter, ImageFont
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB
from unicorn.arm_const import UC_ARM_REG_LR, UC_ARM_REG_PC, UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_SP

from extract_font_text import DATA, FONT, ROOT, TEXT, decompress_lzss, glyph_index, write_tsv
from scenario_rebuild import compress_lzss, rebuild_scenario


TRANSLATIONS = ROOT / "05_AI翻译"
FONT_OUTPUT = ROOT / "06_中文字体/zh_cn"
GAME_OUTPUT = ROOT / "07_修改后的资源/PCSG00510"
UNICODE_TABLE = 0xB8174
PIXELS_START, PIXELS_END = 0x60, 0x400060


def tsv(path, encoding="utf-8-sig"):
    with path.open(encoding=encoding, newline="") as file:
        return list(csv.DictReader(file, delimiter="\t"))


def translations(source, translated, key, *, complete=True):
    original = {row[key]: row for row in tsv(TEXT / source)}
    rows = tsv(TRANSLATIONS / translated)
    keys = {row[key] for row in rows}
    if len(rows) != len(keys) or keys - original.keys() or (complete and keys != original.keys()):
        raise ValueError(f"{translated}: invalid, duplicated or missing row keys")
    for row in rows:
        text = row["translation"]
        if not text or any(not 32 <= ord(c) <= 0xFFFF for c in text):
            raise ValueError(f"{translated}: invalid translation at {row[key]}")
    return [original[row[key]] | {"translation": row["translation"]} for row in rows]


def rebuild_font(font_path, characters):
    codes = tsv(FONT / "game_code_table.tsv")
    mappings = {}
    slots = {}
    used_slots = set()
    for row in codes:
        index = int(row["glyph_index"])
        code = bytes.fromhex(row["code_hex"])
        char = row["character"]
        if char:
            mappings.setdefault(char, code)
            slots[index] = char
        if char or row["eboot_unicode_aliases"]:
            used_slots.add(index)
    added = sorted(characters - mappings.keys())
    free = {}
    for row in codes:
        index = int(row["glyph_index"])
        code = bytes.fromhex(row["code_hex"])
        if index not in used_slots and len(code) == 2:
            free.setdefault(index, code)
    if len(free) < len(added):
        raise ValueError(f"Need {len(added)} spare glyphs, have {len(free)}")
    for char, (index, code) in zip(added, sorted(free.items())):
        mappings[char] = code
        slots[index] = char
    if len({glyph_index(mappings[c]) for c in characters}) != len(characters):
        raise ValueError("Two translated characters resolve to the same atlas slot")
    with TTFont(font_path) as source:
        supported = source.getBestCmap()
        font_name = source["name"].getDebugName(4)
    missing = sorted(set(slots.values()) - {chr(cp) for cp in supported})
    if missing:
        raise ValueError(f"{font_name} is missing glyphs: {''.join(missing)}")

    base = (DATA / "font32.vtx").read_bytes()
    palette = np.frombuffer(base[0x20:PIXELS_START], np.uint8).reshape(16, 4)
    cells = np.zeros((8192, 32, 32), dtype=np.uint8)
    original_flags = base[PIXELS_END:]
    scale = 4
    font = ImageFont.truetype(str(font_path), 28 * scale, layout_engine=ImageFont.Layout.BASIC)
    han_height, han_top = 25, 3
    # Lighten partial fill coverage for thin strokes at dialogue size.
    fill_coverage = np.rint(255 * (np.arange(256) / 255) ** 0.8).astype(np.int16)
    fill_palette = 5 + np.abs(fill_coverage[:, None] - palette[5:, 0]).argmin(axis=1)

    def raster(char, half_width):
        mask = Image.new("L", (32, 32))
        origin_x, origin_y = 16 * scale, 32 * scale
        source_mask = Image.new("L", (64 * scale, 64 * scale))
        ImageDraw.Draw(source_mask).text((origin_x, origin_y), char, font=font, anchor="ls", fill=255)
        bounds = source_mask.getbbox()
        if bounds is None:
            return np.asarray(mask)
        glyph = source_mask.crop(bounds)
        advance = font.getlength(char) / scale
        face_width = 16 if half_width else 32
        inset = 1 if half_width else 2
        width = min(round(glyph.width / scale), face_width - 2 * inset)
        height = min(round(glyph.height / scale), 28)
        # Multi-stroke forms such as 三 have shorter outlines at the same point size.
        if 0x4E00 <= ord(char) <= 0x9FFF and height >= 18:
            if width >= 24:
                width = 26
            x = (face_width - width + 1) // 2
            y, height = han_top, han_height
        else:
            x = round((face_width - advance) / 2 + (bounds[0] - origin_x) / scale)
            y = round(26 + (bounds[1] - origin_y) / scale)
        x = min(max(inset, x), face_width - width - inset)
        y = min(max(2, y), 30 - height)
        glyph = glyph.resize((max(1, width), max(1, height)), Image.Resampling.LANCZOS)
        mask.paste(glyph, (x, y))
        coverage = np.asarray(mask, dtype=np.int16)
        border = np.asarray(mask.filter(ImageFilter.MaxFilter(3)), dtype=np.int16)
        indices = np.abs(border[..., None] - palette[:6, 3]).argmin(axis=2)
        result = np.where(coverage >= 64, fill_palette[coverage], indices)
        # The game samples the full atlas at the edges of each 32-pixel cell.
        result[[0, -1], :] = 0
        result[:, [0, -1]] = 0
        return result

    placeholder = raster("・", False)
    for index, flag in enumerate(original_flags):
        if flag:
            cells[index] = placeholder
    half_slots = {int(row["glyph_index"]) for row in codes if len(row["code_hex"]) == 2}
    for index, char in slots.items():
        cells[index] = raster(char, index in half_slots)
        if not char.isspace() and not cells[index].any():
            raise ValueError(f"Empty glyph {char!r} at slot {index}")
    pixel_indices = cells.reshape(-1)
    packed = (pixel_indices[::2] | pixel_indices[1::2] << 4).tobytes()
    flags = bytes(np.any(cells, axis=(1, 2)).astype(np.uint8))
    rebuilt = base[:PIXELS_START] + packed + flags
    if len(rebuilt) != len(base):
        raise ValueError("VTX size changed")
    atlas = cells.reshape(128, 64, 32, 32).transpose(0, 2, 1, 3).reshape(4096, 2048)
    preview = Image.fromarray(palette[atlas], "RGBA")
    map_rows = [
        {"unicode": f"U+{ord(char):04X}", "character": char, "code_hex": code.hex().upper(),
         "glyph_index": glyph_index(code), "used_in_translation": char in characters}
        for char, code in sorted(mappings.items(), key=lambda item: ord(item[0]))
    ]
    report = {
        "source": str(font_path), "name": font_name, "source_sha256": sha256(font_path.read_bytes()),
        "atlas_slots": len(cells), "translation_characters": len(characters),
        "new_code_assignments": len(added), "missing_glyphs": 0,
        "full_height_han_ink_box": {"top": han_top, "height": han_height, "standard_width": 26},
    }
    return rebuilt, preview, mappings, map_rows, report


def elf_program_headers(elf):
    offset, = unpack_from("<I", elf, 28)
    stride, count = unpack_from("<HH", elf, 42)
    if not elf.startswith(b"\x7fELF") or stride != 32:
        raise ValueError("Unexpected Vita ELF")
    return [(off, unpack_from("<8I", elf, off)) for off in range(offset, offset + stride * count, stride)]


def rebuild_eboot(original, rows, mapping, characters):
    elf = bytearray(original)
    headers = elf_program_headers(elf)
    load = [header for _, header in headers if header[0] == 1]
    address_to_offset = lambda va: next(
        h[1] + va - h[2] for h in load if h[2] <= va < h[2] + h[4]
    )
    chars_to_lut = {ord(c): int.from_bytes(mapping[c], "big") for c in characters}
    for cp, code in chars_to_lut.items():
        pack_into("<H", elf, UNICODE_TABLE + 2 * cp, code)
    # Appending to the RX segment keeps segment-relative symbols and entry offsets
    # stable. The following segments keep their virtual addresses.
    rx_header, rx = headers[0]
    rx_end = rx[1] + rx[4]
    extra = bytearray()
    moved = {}
    placements = {}
    for row in sorted(rows, key=lambda r: int(r["file_offset"], 16)):
        offset, address = int(row["file_offset"], 16), int(row["address"], 16)
        raw = bytes.fromhex(row["raw_hex"])
        if row["encoding"] != "utf-8" or address_to_offset(address) != offset:
            raise ValueError(f"Unexpected EBOOT record at {row['file_offset']}")
        if original[offset:offset + len(raw) + 1] != raw + b"\0":
            raise ValueError(f"EBOOT source bytes differ at {row['file_offset']}")
        new = row["translation"].encode("utf-8") + b"\0"
        end = offset + len(raw) + 1
        # The save-data caption has an eight-byte alignment gap before the next C string.
        padding_limit = 8 if offset == 0xA2538 else (-end) % 4
        gap = original[end:end + padding_limit]
        padding = len(gap) - len(gap.lstrip(b"\0"))
        allocation = end + padding - offset
        if len(new) <= allocation:
            elf[offset:offset + allocation] = new.ljust(allocation, b"\0")
            placements[offset] = (offset, new)
            continue
        # These strings occur only as relocated pointers in EBOOT's data tables.
        start = rx_end + len(extra)
        extra.extend(new)
        extra.extend(bytes(-(rx_end + len(extra)) % 4))
        moved[address - rx[2]] = start - rx[1]
        placements[offset] = (start, new)
    references = defaultdict(list)
    for _, header in headers:
        if header[0] != 0x60000000:
            continue
        position, end = header[1], header[1] + header[4]
        while position < end:
            word, second = unpack_from("<II", elf, position)
            fmt = word & 15
            symbol_segment = (word >> 4) & 15
            dest_segment = (word >> 16) & 15
            relocation_type = (word >> 8) & 255
            if fmt == 0:
                addend, destination = unpack_from("<II", elf, position + 4)
            elif fmt == 1:
                addend = second >> 10
                destination = (word >> 20) | ((second & 1023) << 12)
            else:
                raise ValueError(f"Unexpected relocation format {fmt}")
            if symbol_segment == 0 and addend in moved:
                new_addend = moved[addend]
                if relocation_type != 2 or dest_segment >= len(load):
                    raise ValueError(f"Unexpected reference to moved EBOOT text at {position:#x}")
                target_file = load[dest_segment][1] + destination
                old_pointer, = unpack_from("<I", elf, target_file)
                if old_pointer != rx[2] + addend:
                    raise ValueError(f"Unexpected EBOOT pointer value at {target_file:#x}")
                pack_into("<I", elf, target_file, rx[2] + new_addend)
                pack_into("<I", elf, position + 4,
                          new_addend if fmt == 0 else (new_addend << 10) | (second & 1023))
                references[addend].append(target_file)
            position += 12 if fmt == 0 else 8
    if moved.keys() != references.keys():
        raise ValueError("An expanded EBOOT string has no verified references")
    if extra:
        # Keep the insertion length aligned to all later file segment alignments.
        extra.extend(bytes(-len(extra) % 32))
        if rx[2] + rx[5] + len(extra) > load[1][2]:
            raise ValueError("Expanded EBOOT text would overlap the next load segment")
        pack_into("<II", elf, rx_header + 16, rx[4] + len(extra), rx[5] + len(extra))
        for header_offset, header in headers[1:]:
            if header[1] >= rx_end:
                pack_into("<I", elf, header_offset + 4, header[1] + len(extra))
        elf[rx_end:rx_end] = extra
    for old, (new, encoded) in placements.items():
        if new == old and new >= rx_end:
            new += len(extra)
        if elf[new:new + len(encoded)] != encoded:
            raise ValueError(f"EBOOT text failed readback at {old:#x}")
    for cp, code in chars_to_lut.items():
        if unpack_from("<H", elf, UNICODE_TABLE + len(extra) + 2 * cp)[0] != code:
            raise ValueError(f"Unicode table failed readback for U+{cp:04X}")
    return bytes(elf), {"imported": len(rows), "moved_strings": len(moved), "updated_pointers": sum(map(len, references.values()))}


def wrap_vita_self(elf, retail):
    """Wrap the modified ELF in an unencrypted Vita SELF for Vita3K."""
    if not retail.startswith(b"SCE\0"):
        raise ValueError("Invalid retail SELF header")
    header_size, elf_offset, phdr_offset = 0x1000, 0xA0, 0xE0
    headers = elf_program_headers(elf)
    segments_offset = phdr_offset + 32 * len(headers)
    version_offset = segments_offset + 32 * len(headers)
    control_offset = version_offset + 16
    retail_control, control_size = unpack_from("<QQ", retail, 0x68)
    control = bytearray(retail[retail_control:retail_control + control_size])
    if unpack_from("<II", control) != (4, 0x50):
        raise ValueError("Missing retail SELF digest block")
    control[36:68] = hashlib.sha256(elf).digest()
    control[0x50 + 16:0x50 + 0x110] = bytes(0x100)
    output = bytearray(header_size)
    pack_into("<IIHHIQQ11Q", output, 0, 0x00454353, 3, 0xC0, 1, 0x600,
              header_size, len(elf), header_size + len(elf), 0, 4, 0x80, elf_offset,
              phdr_offset, 0, segments_offset, version_offset, control_offset, len(control))
    output[0x80:0xA0] = retail[0x80:0xA0]
    output[elf_offset:elf_offset + 52] = elf[:52]
    for index, (_, header) in enumerate(headers):
        _, offset, _, _, size, *_ = header
        pack_into("<8I", output, phdr_offset + index * 32, *header)
        pack_into("<4Q", output, segments_offset + index * 32, header_size + offset, size, 1, 2)
    pack_into("<4I", output, version_offset, 1, 0, 16, 0)
    output[control_offset:control_offset + len(control)] = control
    return bytes(output) + elf


def load_thumb_machine(elf):
    cpu = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    cpu.mem_map(0x81000000, 0x4600000)
    for _, (kind, offset, va, _, size, *_) in elf_program_headers(elf):
        if kind == 1:
            cpu.mem_write(va, elf[offset:offset + size])
    cpu.mem_map(0x90000000, 0x10000)
    cpu.mem_map(0x91000000, 0x1000)
    return cpu


def run_thumb(cpu, function, destination, source):
    cpu.reg_write(UC_ARM_REG_R0, destination)
    cpu.reg_write(UC_ARM_REG_R1, source)
    cpu.reg_write(UC_ARM_REG_SP, 0x9000F000)
    cpu.reg_write(UC_ARM_REG_LR, 0x91000001)
    cpu.emu_start(function | 1, 0x91000000, timeout=30_000_000)
    if cpu.reg_read(UC_ARM_REG_PC) != 0x91000000:
        raise ValueError(f"The original Thumb routine at {function:#x} did not return")


def verify_original_routines(elf, compressed, decompressed, eboot_rows, encode):
    cpu = load_thumb_machine(elf)
    for address, size in [(0x92000000, len(compressed)), (0x93000000, len(decompressed))]:
        cpu.mem_map(address, (size + 0xFFF) & ~0xFFF)
    cpu.mem_write(0x92000000, compressed)
    run_thumb(cpu, 0x8104DA28, 0x92000000, 0x93000000)
    if bytes(cpu.mem_read(0x93000000, len(decompressed))) != decompressed:
        raise ValueError("The original LZSS routine produced different bytes")
    for row in eboot_rows:
        text = row["translation"]
        expected = encode(text) + b"\0"
        cpu.mem_write(0x90000000, text.encode("utf-8") + b"\0")
        cpu.mem_write(0x90004000, b"\xff" * len(expected))
        run_thumb(cpu, 0x8100D77E, 0x90004000, 0x90000000)
        if bytes(cpu.mem_read(0x90004000, len(expected))) != expected:
            raise ValueError(f"Original EBOOT converter disagrees at {row['file_offset']}")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--font", type=Path,
                        default=Path(os.environ["WINDIR"]) / "Fonts/Noto Sans SC (TrueType).otf")
    args = parser.parse_args()
    messages = translations("sn_messages.tsv", "sn_messages_translated.tsv", "text_offset")
    choices = translations("sn_choices.tsv", "sn_choices_translated.tsv", "text_offset")
    candidates = translations("eboot_string_candidates.tsv", "eboot_string_candidates_translated.tsv",
                              "file_offset", complete=False)
    utf8 = translations("eboot_utf8_japanese.tsv", "eboot_utf8_japanese_translated.tsv", "file_offset")
    eboot_rows = {}
    for row in candidates + utf8:
        key = row["file_offset"]
        if row["translation"]:
            if key in eboot_rows and row != eboot_rows[key]:
                raise ValueError(f"Conflicting EBOOT translations at {key}")
            eboot_rows[key] = row
    texts = messages + choices + list(eboot_rows.values())
    characters = set().union(*(set(row["translation"]) for row in texts))
    print(f"Rebuilding the single-source font for {len(characters)} characters", flush=True)
    font, atlas, mapping, map_rows, font_report = rebuild_font(args.font, characters)
    print("Importing and verifying every script string and jump", flush=True)
    def encode(text):
        return b"".join(mapping[char] for char in text)

    sn, sn_report = rebuild_scenario((TEXT / "sn_decompressed.bin").read_bytes(), messages + choices, encode)
    print(f"Compressing {len(sn):,} scenario bytes", flush=True)
    compressed = compress_lzss(sn)
    decoded, consumed = decompress_lzss(compressed)
    if decoded != sn or consumed != len(compressed):
        raise ValueError("LZSS round trip failed")
    print("Verifying compression and EBOOT encoding with the original game routines", flush=True)
    original_elf = (DATA.parent / "PCSG00510.elf").read_bytes()
    eboot, elf_report = rebuild_eboot(original_elf, list(eboot_rows.values()), mapping, characters)
    verify_original_routines(eboot, compressed, sn, eboot_rows.values(), encode)
    FONT_OUTPUT.mkdir(parents=True, exist_ok=True)
    (GAME_OUTPUT / "data").mkdir(parents=True, exist_ok=True)
    self_file = wrap_vita_self(eboot, (DATA.parent / "eboot.bin").read_bytes())
    products = {"eboot.bin": self_file, "data/font32.vtx": font, "data/sn.bin": compressed}
    for path, data in products.items():
        (GAME_OUTPUT / path).write_bytes(data)
    atlas.save(FONT_OUTPUT / "font32_atlas.png")
    write_tsv(FONT_OUTPUT / "game_zh_cn.tsv", map_rows, list(map_rows[0]))
    token_changes = [
        row["text_offset"] for row in messages
        if re.findall(r"%[A-Za-z]", bytes.fromhex(row["raw_hex"]).decode("cp932"))
        != re.findall(r"%[A-Za-z]", row["translation"])
    ]
    report = {
        "font": font_report,
        "scenario": sn_report | {"messages": len(messages), "choices": len(choices),
                                 "decompressed_size": len(sn), "decompressed_sha256": sha256(sn),
                                 "original_decompressor_match": True,
                                 "preserved_translation_control_token_differences": token_changes},
        "eboot": elf_report | {"original_converter_verified": len(eboot_rows)},
        "files": {path: {"size": len(data), "sha256": sha256(data)} for path, data in products.items()},
    }
    (GAME_OUTPUT.parent / "import_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)


if __name__ == "__main__":
    main()
