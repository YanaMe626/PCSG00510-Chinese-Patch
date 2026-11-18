"""Extract message/name/choice records and retain a separate string audit.

Opcode table: 0x810B877C. 0x45/46/47 handlers: 0x810307B2,
0x8103192A, 0x81032962. Choices 0x31/32: 0x81029480/0x81029EDE.
The bytecode is not fully disassembled: candidate scanning is explicit.
"""
from pathlib import Path
from bisect import bisect_right
from collections import Counter
import csv
import hashlib
import json
import re
import struct
from elftools.elf.elffile import ELFFile
from extract_font_text import write_tsv, glyph_index

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "04_日文原文"
REPORT = ROOT / "03_文件结构分析/ghidra"
TOKEN = rb"(?:[\x20-\x7e\xa1-\xdf]|[\x81-\x9f\xe0-\xfc][\x40-\x7e\x80-\xfc])"
STRING = re.compile(TOKEN + rb"*\x00")
UTF8_STRING = re.compile(rb"(?:[\x20-\x7e]|[\xc2-\xdf][\x80-\xbf]|[\xe0-\xef][\x80-\xbf]{2}|[\xf0-\xf4][\x80-\xbf]{3}){2,}\x00")


def decode_at(data, pos, limit):
    end = data.find(b"\0", pos, min(limit, pos + 4096))
    if end < pos:
        return None
    raw = data[pos:end]
    if not re.fullmatch(TOKEN + rb"*", raw):
        return None
    try:
        text = raw.decode("cp932")
    except UnicodeDecodeError:
        return None
    # Exclude control and private-use bytes interpreted as nonstandard CP932.
    if any(ord(c) < 0x20 or 0xE000 <= ord(c) <= 0xF8FF for c in text):
        return None
    return end, raw, text


def japanese(text):
    return any(0x3000 <= ord(c) <= 0x30FF or 0x4E00 <= ord(c) <= 0x9FFF or 0xFF01 <= ord(c) <= 0xFF9F for c in text)


def main():
    data = (OUT / "sn_decompressed.bin").read_bytes()
    table_end = struct.unpack_from("<I", data)[0]
    if table_end % 16:
        raise ValueError("Unaligned script table")
    entries = []
    for idx in range(table_end // 16):
        off, size, a, b = struct.unpack_from("<4I", data, idx * 16)
        if off < table_end or off + size > len(data) or a or b:
            raise ValueError("Invalid script directory")
        if entries and off != entries[-1]["offset"] + entries[-1]["size"]:
            raise ValueError("Non-contiguous script entries")
        entries.append({"entry": idx, "offset": off, "size": size})
    if entries[-1]["offset"] + entries[-1]["size"] != len(data):
        raise ValueError("Script directory does not cover decompressed file")
    (OUT / "sn_entries").mkdir(exist_ok=True)
    for e in entries:
        (OUT / "sn_entries" / f"{e['entry']:03d}.bin").write_bytes(data[e["offset"]:e["offset"] + e["size"]])
    write_tsv(OUT / "sn_entries.tsv", entries, list(entries[0]))
    records = []
    choices = []
    rejected = []
    for entry in entries:
        start, limit = entry["offset"], entry["offset"] + entry["size"]
        pos = start
        while pos < limit - 3:
            op = data[pos]
            if op not in (0x45, 0x46, 0x47):
                pos += 1
                continue
            window = struct.unpack_from("<h", data, pos + 1)[0]
            # The game's four text windows and default window.
            if window not in (-1, 10, 13, 0x46, 0x47):
                pos += 1
                continue
            textpos = pos + 3
            message_id = ""
            if window in (-1, 10):
                if pos + 5 >= limit:
                    pos += 1
                    continue
                message_id = struct.unpack_from("<h", data, pos + 3)[0]
                textpos += 2
            result = decode_at(data, textpos, limit)
            if result is None:
                pos += 1
                continue
            end, raw, text = result
            if not text:
                pos += 1
                continue
            if message_id != "" and not -1 <= message_id < 30000:
                pos += 1
                continue
            records.append({"entry": entry["entry"], "opcode_offset": f"0x{pos:X}",
                            "text_offset": f"0x{textpos:X}", "entry_text_offset": f"0x{textpos-start:X}",
                            "opcode": f"0x{op:02X}", "window": window, "message_id": message_id,
                            "byte_length": len(raw), "original": text, "translation": "",
                            "raw_hex": raw.hex().upper(), "extraction": "opcode_pattern"})
            pos = end + 1
        pos = start
        while pos < limit - 17:
            match = re.search(rb"[\x31\x32]", data[pos:limit-16])
            if match is None:
                break
            pos += match.start()
            variable, count, flag = struct.unpack_from("<3H", data, pos + 1)
            if not (1 <= count <= 12 and flag < 0x100):
                pos += 1
                continue
            p = pos + 7
            batch = []
            for i in range(count):
                if p + 10 >= limit:
                    break
                enabled, a, b, target = struct.unpack_from("<3HI", data, p)
                if enabled not in (0, 1, 0xFFFF) and not 0x8000 <= enabled <= 0x80FF:
                    break
                if target >= entry["size"]:
                    break
                result = decode_at(data, p + 10, limit)
                if result is None:
                    break
                end, raw, text = result
                batch.append({"entry": entry["entry"], "opcode_offset": f"0x{pos:X}", "opcode": f"0x{data[pos]:02X}", "option": i,
                              "text_offset": f"0x{p+10:X}", "jump_target": f"0x{target:X}",
                              "byte_length": len(raw), "original": text, "translation": "",
                              "raw_hex": raw.hex().upper(), "extraction": "choice_pattern"})
                p = end + 1
            if len(batch) == count and any(japanese(r["original"]) for r in batch):
                choices.extend(batch)
                pos = p
            else:
                pos += 1
    if records:
        write_tsv(OUT / "sn_messages.tsv", records, list(records[0]))
    if choices:
        write_tsv(OUT / "sn_choices.tsv", choices, list(choices[0]))
    confirmed_ranges = sorted((int(r["text_offset"], 16), int(r["text_offset"], 16) + r["byte_length"]) for r in records + choices)
    confirmed_starts = [a for a, b in confirmed_ranges]
    starts = [e["offset"] for e in entries]
    audit = []
    for match in STRING.finditer(data, table_end):
        raw = match.group()[:-1]
        try:
            text = raw.decode("cp932")
        except UnicodeDecodeError:
            continue
        if not japanese(text) or len(text) < 2 or any(0xE000 <= ord(c) <= 0xF8FF for c in text):
            continue
        near = bisect_right(confirmed_starts, match.end())
        overlap = any(a < match.end() and match.start() <= b for a, b in confirmed_ranges[max(0, near - 2):near])
        audit.append({"entry": bisect_right(starts, match.start()) - 1, "offset": f"0x{match.start():X}",
                      "byte_length": len(raw), "text": text,
                      "overlaps_message_or_choice": overlap,
                      "status": "candidate_not_instruction_verified"})
    if audit:
        write_tsv(OUT / "sn_string_candidates.tsv", audit, list(audit[0]))
    # Scan the ELF's initialized PT_LOAD data area, excluding executable code.
    elf_path = ROOT / "02_解包资源/PCSG00510_decrypted/PCSG00510.elf"
    with elf_path.open("rb") as f:
        segments = [s for s in ELFFile(f).iter_segments() if s["p_type"] == "PT_LOAD"]
    elf = elf_path.read_bytes()
    # In this Vita ELF, rodata is included in the RX segment after game code.
    eboot_rows = []
    for seg in segments:
        begin = int(seg["p_offset"])
        end = begin + int(seg["p_filesz"])
        if seg["p_flags"] & 1:
            begin = max(begin, 0x95000 + 0xE0)
        utf8_ranges = []
        for match in UTF8_STRING.finditer(elf, begin, end):
            raw = match.group()[:-1]
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue
            if not japanese(text):
                continue
            va = int(seg["p_vaddr"]) + match.start() - int(seg["p_offset"])
            utf8_ranges.append((match.start(), match.end()))
            eboot_rows.append({"file_offset": f"0x{match.start():X}", "address": f"0x{va:08X}",
                               "encoding": "utf-8", "byte_length": len(raw), "original": text, "translation": "",
                               "raw_hex": raw.hex().upper(), "status": "string_candidate"})
        for match in STRING.finditer(elf, begin, end):
            if any(a < match.end() and match.start() < b for a, b in utf8_ranges):
                continue
            raw = match.group()[:-1]
            try:
                text = raw.decode("cp932")
            except UnicodeDecodeError:
                continue
            if not japanese(text) or len(text) < 2 or any(0xE000 <= ord(c) <= 0xF8FF for c in text):
                continue
            va = int(seg["p_vaddr"]) + match.start() - int(seg["p_offset"])
            eboot_rows.append({"file_offset": f"0x{match.start():X}", "address": f"0x{va:08X}",
                               "encoding": "cp932", "byte_length": len(raw), "original": text, "translation": "",
                               "raw_hex": raw.hex().upper(), "status": "string_candidate"})
    if eboot_rows:
        eboot_rows.sort(key=lambda row: int(row["file_offset"], 16))
        write_tsv(OUT / "eboot_string_candidates.tsv", eboot_rows, list(eboot_rows[0]))
        clean = [r for r in eboot_rows if r["encoding"] == "utf-8" and
                 any(0x3040 <= ord(c) <= 0x30FF or 0x4E00 <= ord(c) <= 0x9FFF for c in r["original"])]
        write_tsv(OUT / "eboot_utf8_japanese.tsv", clean, list(eboot_rows[0]))
    message_text = []
    for r in records:
        message_text.append(f"[{r['entry']:03d} {r['text_offset']} {r['opcode']} window={r['window']}] {r['original']}")
    (OUT / "sn_readable.txt").write_text("\n".join(message_text) + "\n", encoding="utf-8-sig")
    report = {"entries": len(entries), "directory_covers_entire_file": True,
              "message_records": len(records), "message_opcode_counts": dict(Counter(r["opcode"] for r in records)),
              "choice_options": len(choices), "audit_string_candidates": len(audit), "eboot_string_candidates": len(eboot_rows),
              "eboot_encoding_counts": dict(Counter(r["encoding"] for r in eboot_rows)),
              "message_bytes_roundtrip": all(r["original"].encode("cp932").hex().upper() == r["raw_hex"] for r in records),
              "limitations": "Message/choice records use validated opcode patterns, not full bytecode traversal. Candidate tables may contain false positives; full text coverage is not claimed."}
    (REPORT / "text_extraction_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    print("First messages:")
    for row in records[:10]:
        print(row["entry"], row["text_offset"], row["original"])


if __name__ == "__main__":
    main()
