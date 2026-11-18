"""Download pinned upstream portable tools; keep sources and checksums on disk."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
TOOLS = ROOT / "tools"
PACKAGES = [
    ("ghidra", "NationalSecurityAgency/ghidra", "Ghidra_12.1.3_build", "ghidra_12.1.3_PUBLIC_20260817.zip"),
    ("jdk", "adoptium/temurin21-binaries", "jdk-21.0.13+9", "OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.zip"),
    ("vita_loader", "CreepNT/VitaLoaderRedux", "1.09", "ghidra_12.1.3_PUBLIC_20260903_VitaLoaderRedux.zip"),
]


def install(package):
    name, repo, tag, asset_name = package
    url = "https://api.github.com/repos/" + repo + "/releases/tags/" + urllib.parse.quote(tag, safe="")
    release = json.load(urllib.request.urlopen(url, timeout=45))
    asset = next(a for a in release["assets"] if a["name"] == asset_name)
    archive = TOOLS / "downloads" / asset_name
    archive.parent.mkdir(parents=True, exist_ok=True)
    if not archive.exists() or archive.stat().st_size != asset["size"]:
        print("Downloading", asset_name, asset["size"], flush=True)
        urllib.request.urlretrieve(asset["browser_download_url"], archive)
    digest = hashlib.file_digest(archive.open("rb"), "sha256").hexdigest()
    expected = asset.get("digest")
    if expected and expected != "sha256:" + digest:
        raise ValueError("Checksum mismatch: " + asset_name)
    dest = TOOLS / name
    with zipfile.ZipFile(archive) as z:
        # Archives are pinned releases; still reject paths leaving destination.
        for member in z.namelist():
            if not (dest / member).resolve().is_relative_to(dest.resolve()):
                raise ValueError("Unsafe archive path: " + member)
        z.extractall(dest)
    print("Ready", name, flush=True)
    return {"name": name, "repository": "https://github.com/" + repo,
            "release": release["html_url"], "download": asset["browser_download_url"],
            "archive": str(archive), "sha256": digest,
            "github_digest_verified": bool(expected)}


if __name__ == "__main__":
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        records = list(pool.map(install, PACKAGES))
    ghidra = next((TOOLS / "ghidra").glob("ghidra_*"))
    extroot = ghidra / "Ghidra" / "Extensions"
    import shutil
    for extension in (TOOLS / "vita_loader").iterdir():
        if extension.is_dir():
            shutil.copytree(extension, extroot / extension.name, dirs_exist_ok=True)
    (TOOLS / "sources.json").write_text(json.dumps(records, indent=2) + "\n", encoding="utf-8")
    print("Ghidra:", ghidra, flush=True)
