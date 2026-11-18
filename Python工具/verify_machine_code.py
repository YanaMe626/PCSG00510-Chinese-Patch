"""Validate reconstructed algorithms against original Thumb machine code."""
from pathlib import Path
import hashlib
import importlib.util
import json
import struct
import sys
from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_HOOK_MEM_INVALID
from unicorn.arm_const import *

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("extract", Path(__file__).with_name("extract_font_text.py"))
extract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extract)


def main():
    elf = ROOT / "02_解包资源/PCSG00510_decrypted/PCSG00510.elf"
    uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB)
    uc.reg_write(UC_ARM_REG_C1_C0_2, 0xF00000)
    uc.reg_write(UC_ARM_REG_FPEXC, 1 << 30)
    uc.mem_map(0x81000000, 0x4600000)
    with elf.open("rb") as f:
        for seg in ELFFile(f).iter_segments():
            if seg["p_type"] == "PT_LOAD":
                uc.mem_write(seg["p_vaddr"], seg.data())
    uc.mem_map(0x90000000, 0x10000)
    uc.mem_map(0x91000000, 0x1000)
    uc.mem_map(0x92000000, 0x600000)
    uc.mem_map(0x93000000, 0x600000)
    def invalid(uc, access, address, size, value, data):
        print("Invalid access", hex(address), "PC", hex(uc.reg_read(UC_ARM_REG_PC)), flush=True)
        return False
    uc.hook_add(UC_HOOK_MEM_INVALID, invalid)
    records = []
    for first in list(range(0x20, 0x7F)) + list(range(0xA1, 0xE0)):
        records.append(bytes([first]))
    for first in list(range(0x81, 0xA0)) + list(range(0xE0, 0xFD)):
        for second in range(0x40, 0xFD):
            if second != 0x7F:
                records.append(bytes([first, second]))
    for raw in records:
        uc.mem_write(0x81116EC0, b"\0\0\xff\xff")
        uc.mem_write(0x81102ED6, b"\x01\0")
        uc.mem_write(0x90001000, raw + b"\0\0")
        # Text pointer is R0; the decompiler's first two parameters are VFP values.
        uc.reg_write(UC_ARM_REG_R0, 0x90001000)
        uc.reg_write(UC_ARM_REG_R1, 0)
        uc.reg_write(UC_ARM_REG_R2, 0x90001000)
        uc.reg_write(UC_ARM_REG_R3, 0)
        uc.reg_write(UC_ARM_REG_SP, 0x9000F000)
        uc.reg_write(UC_ARM_REG_LR, 0x91000001)
        uc.emu_start(0x8100D0B3, 0x91000000, count=1000)
        actual = struct.unpack("<H", uc.mem_read(0x81102EC8, 2))[0]
        expected = extract.glyph_index(raw) & 0xFFFF
        if actual != expected or uc.reg_read(UC_ARM_REG_R0) != len(raw):
            raise AssertionError((raw.hex(), actual, expected))
    print("Code-to-slot mapping matched", len(records), "original machine-code executions", flush=True)
    compressed = (ROOT / "02_解包资源/PCSG00510_decrypted/data/sn.bin").read_bytes()
    expected = (ROOT / "04_日文原文/sn_decompressed.bin").read_bytes()
    uc.mem_write(0x92000000, compressed)
    uc.reg_write(UC_ARM_REG_R0, 0x92000000)
    uc.reg_write(UC_ARM_REG_R1, 0x93000000)
    uc.reg_write(UC_ARM_REG_SP, 0x9000F000)
    uc.reg_write(UC_ARM_REG_LR, 0x91000001)
    # No instruction tracing: execute the full original LZSS routine.
    uc.emu_start(0x8104DA29, 0x91000000, timeout=120000000)
    actual = bytes(uc.mem_read(0x93000000, len(expected)))
    if uc.reg_read(UC_ARM_REG_PC) != 0x91000000:
        raise AssertionError("Decompressor did not return before timeout")
    if actual != expected:
        raise AssertionError("Python LZSS differs from original machine code")
    report = {"mapping_function": "0x8100D0B2", "mapping_cases": len(records), "mapping_mismatches": 0,
              "decompress_function": "0x8104DA28", "decompressed_bytes": len(expected),
              "decompress_byte_exact_match": True, "output_sha256": hashlib.sha256(actual).hexdigest()}
    (ROOT / "03_文件结构分析/ghidra/machine_code_verification.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
