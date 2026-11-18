"""Rebuild PCSG00510 scenario entries and relocate their VM operands."""

from bisect import bisect_right
from collections import defaultdict, deque
from struct import pack, pack_into, unpack_from


# Operand lengths, excluding the opcode byte. Variable-length cases are below.
FIXED = {
    0x00: 0, 0x01: 4, 0x02: 4, 0x03: 4, 0x04: 4, 0x05: 0,
    **dict.fromkeys(range(0x06, 0x0C), 8),
    0x0C: 6, 0x0D: 6, 0x0F: 0,
    **dict.fromkeys(range(0x10, 0x19), 4),
    0x19: 8, 0x1A: 4, 0x1B: 0, 0x1C: 0,
    0x1D: 6, 0x1E: 10, 0x1F: 12, 0x20: 6, 0x21: 6, 0x22: 4,
    0x23: 8, 0x24: 6, 0x25: 4, 0x26: 0, 0x27: 0, 0x2A: 0,
    0x2C: 2, 0x2D: 4, 0x2E: 0, 0x2F: 2, 0x30: 10, 0x33: 0,
    0x34: 10, 0x35: 4, 0x36: 3, 0x37: 0, 0x38: 3, 0x39: 4, 0x3A: 4,
    0x3B: 2, 0x3C: 2, 0x3D: 0, 0x3F: 2, 0x40: 0, 0x42: 8, 0x43: 4,
    0x44: 7, 0x48: 2, 0x49: 4, 0x4A: 2, 0x4B: 4, 0x4C: 6, 0x4D: 6,
    0x4E: 4, 0x4F: 4, 0x50: 4, 0x51: 6, 0x52: 10, 0x53: 2, 0x55: 4,
    0x56: 2, 0x57: 0, 0x58: 2, 0x59: 0, 0x5A: 0, 0x5B: 10, 0x5C: 6,
    0x5D: 4, 0x5E: 2, 0x5F: 0, 0x60: 6, 0x61: 6, 0x62: 4, 0x63: 10,
    0x64: 4, 0x65: 2, 0x66: 2, 0x67: 0, 0x68: 10, 0x69: 4, 0x6A: 4,
    0x6B: 2, 0x6C: 16, 0x6D: 2, 0x6E: 4, 0x6F: 6, 0x70: 0, 0x71: 7,
    0x72: 4, 0x73: 10, 0x74: 6, 0x75: 4, 0x76: 0, 0x77: 2, 0x78: 2,
    0x79: 4, 0x7A: 6, 0x7B: 4, 0x7C: 4, 0x7D: 2, 0x7E: 2, 0x7F: 2,
    0x80: 4, 0x81: 2, 0x82: 2, 0x83: 4, 0x84: 0, 0x87: 0, 0x88: 0,
    0x89: 0, 0x8A: 2, 0x8B: 4, 0x8C: 4, 0x8D: 0, 0x8E: 0, 0x8F: 0,
    0x91: 0, 0x92: 14, 0x93: 8, 0x94: 6, 0xFF: 0,
}
RELATIVE = {0x01: 1, 0x03: 1, **dict.fromkeys(range(0x06, 0x0C), 5),
            0x0C: 3, 0x0D: 3, 0x19: 3, 0x24: 3, 0x55: 1, 0x79: 1}


def parse_entry(data):
    strings = {}
    relocations = {}
    commands = set()
    pending = deque()
    header_size, = unpack_from("<I", data)
    if not 4 <= header_size <= len(data) or header_size % 4:
        raise ValueError(f"Invalid entry header size {header_size}")
    for pos in range(0, header_size, 4):
        target, = unpack_from("<I", data, pos)
        relocations[pos] = target
        pending.append(target)

    def text(pos, op):
        end = data.index(0, pos)
        strings[pos] = (op, end)
        return end + 1

    def target_at(pos, optional=False, executable=True):
        target, = unpack_from("<I", data, pos)
        if optional and target == 0:
            return
        if not header_size <= target < len(data):
            raise ValueError(f"Invalid destination {target:#x} at {pos:#x}")
        relocations[pos] = target
        if executable:
            pending.append(target)

    while pending:
        pos = pending.popleft()
        while pos < len(data) and pos not in commands:
            commands.add(pos)
            op = data[pos]
            p = pos + 1
            try:
                if op in FIXED:
                    if op in RELATIVE:
                        target_at(pos + RELATIVE[op], executable=op not in (0x19, 0x24, 0x55, 0x79))
                    p += FIXED[op]
                elif op == 0x0E:
                    count, = unpack_from("<H", data, p + 2)
                    p += 4
                    for _ in range(count):
                        target_at(p + 2)
                        p += 6
                elif op in (0x28, 0x29, 0x41, 0x86):
                    p = text(p + {0x28: 2, 0x29: 4, 0x41: 0, 0x86: 4}[op], op)
                elif op in (0x31, 0x32, 0x54):
                    count_at, header = (4, 8) if op == 0x54 else (2, 6)
                    count, = unpack_from("<H", data, p + count_at)
                    if count > 64:
                        raise ValueError(f"Invalid choice count {count}")
                    p += header
                    for _ in range(count):
                        if op != 0x54:
                            target_at(p + 6, optional=True)
                        p = text(p + (2 if op == 0x54 else 10), op)
                elif op == 0x3E:
                    kind, = unpack_from("<H", data, p)
                    p += 4 if kind == 1 else 2
                elif op in (0x45, 0x46, 0x47, 0x85, 0x90):
                    window, = unpack_from("<h", data, p)
                    p = text(p + (4 if window in (-1, 10) else 2), op)
                else:
                    raise ValueError(f"Unknown opcode {op:#04x}")
                if p > len(data):
                    raise ValueError("Truncated instruction")
            except (ValueError, IndexError) as error:
                raise ValueError(f"{pos:#x}: {error}") from error
            if op in (0x00, 0x01, 0x02, 0x05, 0x57):
                break
            pos = p
    return strings, relocations, commands


def rebuild_scenario(original, rows, encode):
    directory_size, = unpack_from("<I", original)
    directory = bytearray(original[:directory_size])
    result = bytearray(directory)
    by_entry = defaultdict(list)
    for row in rows:
        by_entry[int(row["entry"])].append(row)
    imported = 0
    moved_operands = 0
    for entry in range(directory_size // 16):
        offset, size = unpack_from("<II", directory, entry * 16)
        old = original[offset:offset + size]
        if entry not in by_entry:
            pack_into("<II", result, entry * 16, len(result), size)
            result.extend(old)
            continue
        try:
            strings, relocations, _ = parse_entry(old)
        except ValueError as error:
            raise ValueError(f"Entry {entry}: {error}") from error
        new = bytearray()
        ends, shifts, expected = [], [], {}
        last = 0
        for row in sorted(by_entry[entry], key=lambda r: int(r["text_offset"], 16)):
            begin = int(row["text_offset"], 16) - offset
            raw = bytes.fromhex(row["raw_hex"])
            end = begin + len(raw)
            if begin < last or strings.get(begin) != (int(row["opcode"], 16), end):
                raise ValueError(f"Entry {entry} does not have the expected string at {begin:#x}")
            if old[begin:end + 1] != raw + b"\0":
                raise ValueError(f"Source bytes differ at {row['text_offset']}")
            new.extend(old[last:begin])
            encoded = encode(row["translation"])
            expected[len(new)] = (int(row["opcode"], 16), encoded)
            new.extend(encoded + b"\0")
            last = end + 1
            ends.append(last)
            shifts.append(len(new) - last)
            imported += 1
        new.extend(old[last:])

        def relocate(pos):
            count = bisect_right(ends, pos)
            return pos + (shifts[count - 1] if count else 0)

        for pos, destination in relocations.items():
            new_pos, new_destination = relocate(pos), relocate(destination)
            pack_into("<I", new, new_pos, new_destination)
            moved_operands += new_destination != destination
        strings_after, relocs_after, _ = parse_entry(new)
        if relocs_after != {relocate(p): relocate(t) for p, t in relocations.items()}:
            raise ValueError(f"Entry {entry}: relocation round trip failed")
        for pos, (op, encoded) in expected.items():
            end = pos + len(encoded)
            if strings_after.get(pos) != (op, end) or new[pos:end] != encoded:
                raise ValueError(f"Entry {entry}: text round trip failed at {pos:#x}")
        new.extend(bytes(-len(new) % 16))
        pack_into("<II", result, entry * 16, len(result), len(new))
        result.extend(new)
    return bytes(result), {"imported": imported, "relocated_operands": moved_operands}


def compress_lzss(data):
    """Encode matches with a 4096-byte ring and groups of eight tokens."""
    output = bytearray(pack("<I", len(data)))
    history = defaultdict(deque)
    pos = 0
    while pos < len(data):
        header = len(output)
        output.append(0)
        for bit in range(8):
            if pos == len(data):
                break
            limit = min(18, len(data) - pos)
            match_length, match_pos = 0, 0
            if limit >= 3:
                key = data[pos:pos + 3]
                for previous in reversed(history[key]):
                    count = 3
                    while count < limit and data[previous + count] == data[pos + count]:
                        count += 1
                    if count > match_length:
                        match_length, match_pos = count, previous
                    if count == limit:
                        break
            if match_length >= 3:
                ring_index = (0xFEE + match_pos) & 0xFFF
                output.extend((ring_index & 0xFF, (ring_index >> 4 & 0xF0) | (match_length - 3)))
            else:
                output[header] |= 1 << bit
                output.append(data[pos])
                match_length = 1
            for i in range(pos, pos + match_length):
                if i >= 4096:
                    old_key = data[i - 4096:i - 4093]
                    queue = history[old_key]
                    queue.popleft()
                    if not queue:
                        del history[old_key]
                history[data[i:i + 3]].append(i)
            pos += match_length
    return bytes(output)
