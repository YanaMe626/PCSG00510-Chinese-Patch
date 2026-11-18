"""PFS -> SELF/resources -> ELF, using only the game's own work.bin.

F00D transform reference: Vita3K/psvpfsparser/F00DNativeKeyEncryptor.cpp.
An ephemeral loopback adapter lets the original upstream Windows parser
use that local transform. No license data is sent over the network.
"""
from argparse import ArgumentParser
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse
import hashlib
import json
import re
import struct
import subprocess
import sys
import threading
from Crypto.Cipher import AES

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "01_游戏文件"
OUTPUT = ROOT / "02_解包资源" / "PCSG00510_decrypted"
REPORTS = ROOT / "03_文件结构分析" / "ghidra"
CONTRACT_KEY0 = bytes.fromhex("e12213b48016b0e99ab81f8ec02ad4a2")


class LocalF00D(BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_GET(self):
        try:
            key = bytes.fromhex(parse_qs(urlparse(self.path).query)["key"][0])
            if len(key) not in (16, 32):
                raise ValueError("invalid key length")
            drv = AES.new(CONTRACT_KEY0, AES.MODE_ECB).decrypt(key)
            payload = json.dumps({"key": key.hex(), "drv_key": drv.hex()}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (KeyError, ValueError):
            self.send_error(400)


def main():
    cli = ArgumentParser(description=__doc__)
    cli.add_argument("--source", type=Path, default=SOURCE)
    cli.add_argument("--parser", type=Path, default=ROOT / "tools/pfsparser/psvpfsparser.exe")
    args = cli.parse_args()
    REPORTS.mkdir(parents=True, exist_ok=True)
    rif = (args.source / "sce_sys/package/work.bin").read_bytes()
    content_id = rif[0x10:0x40].rstrip(b"\0").decode("ascii")
    if not content_id.startswith("JP0022-PCSG00510_"):
        raise ValueError("Unexpected game identity")
    key = rif[0x50:0x60]
    if not (OUTPUT / "data/font32.vtx").exists():
        if not args.parser.is_file():
            raise FileNotFoundError(f"Place the PFS parser at {args.parser} or pass --parser")
        server = ThreadingHTTPServer(("127.0.0.1", 0), LocalF00D)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        command = [str(args.parser.resolve()), "-i", str(args.source.resolve()), "-o", str(OUTPUT),
                   "-k", key.hex(), "-f", "http://127.0.0.1:" + str(server.server_port)]
        print("Decrypting PFS locally:", content_id, flush=True)
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=600)
        finally:
            server.shutdown()
            server.server_close()
        log = result.stdout.decode("utf-8", "replace")
        log = re.sub(r"(?i)\b[0-9a-f]{32,64}\b", "[redacted key/hash]", log)
        (REPORTS / "pfs_decrypt.log").write_text(log, encoding="utf-8")
        print(log[-4500:], flush=True)
        if result.returncode:
            raise RuntimeError("PFS parser failed with " + str(result.returncode))

    self_path = OUTPUT / "eboot.bin"
    if self_path.read_bytes()[:4] != b"SCE\0":
        raise ValueError("PFS output is not a Vita SELF")
    vendor = ROOT / "tools" / "psvdec"
    if not (vendor / "self2elf.py").is_file():
        raise FileNotFoundError(f"Place the psvdec Python files in {vendor}")
    sys.path.insert(0, str(vendor))
    from self2elf import self2elf
    from contextlib import redirect_stdout
    elf_path = OUTPUT / "PCSG00510.elf"
    with self_path.open("rb") as src, elf_path.open("wb") as dest:
        with (REPORTS / "self_decrypt.log").open("w", encoding="utf-8") as log:
            with redirect_stdout(log):
                self2elf(src, dest, key, silent=True)
    elf = elf_path.read_bytes()
    if elf[:6] != b"\x7fELF\x01\x01":
        raise ValueError("Invalid ELF32 output")
    digest_constant = bytes.fromhex("627CB1808AB938E32C8C091708726A579E2586E4")
    self_data = self_path.read_bytes()
    offset = self_data.find(digest_constant)
    if offset < 0:
        raise ValueError("SELF digest record missing")
    expected = self_data[offset + len(digest_constant):offset + len(digest_constant) + 32].hex()
    actual = hashlib.sha256(elf).hexdigest()
    if actual != expected:
        raise ValueError("ELF SHA256 does not match the SELF digest")
    header = struct.unpack_from("<16sHHIIIIIHHHHHH", elf)
    phdrs = [struct.unpack_from("<8I", elf, header[5] + i * header[9]) for i in range(header[10])]
    records = {}
    for name in ("eboot.bin", "PCSG00510.elf", "data/font32.vtx", "data/sn.bin", "data/sys.cpk"):
        path = OUTPUT / name
        with path.open("rb") as f:
            digest = hashlib.file_digest(f, "sha256").hexdigest()
        records[name] = {"size": path.stat().st_size, "sha256": digest,
                         "magic": path.open("rb").read(16).hex(" ")}
    report = {"content_id": content_id, "elf_digest_verified": True,
              "source": str(args.source.resolve()), "output": str(OUTPUT), "files": records,
              "elf_program_headers": phdrs}
    (REPORTS / "decryption_report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)


if __name__ == "__main__":
    main()
