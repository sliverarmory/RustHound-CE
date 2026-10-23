#!/usr/bin/env python3
"""Build a deterministic Sliver Armory package around a Windows RustHound DLL."""

import argparse
import gzip
import hashlib
import io
import json
import re
import tarfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DLL_NAME = "dist/rusthound-ce-windows-amd64.dll"


def add_file(archive: tarfile.TarFile, name: str, data: bytes) -> None:
    entry = tarfile.TarInfo(name)
    entry.size = len(data)
    entry.mode = 0o600 if name == "extension.json" else 0o644
    entry.mtime = 0
    archive.addfile(entry, io.BytesIO(data))


def package(dll: Path, version: str, out: Path) -> tuple[Path, Path]:
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("version must be a stable semantic version")
    payload = dll.read_bytes()
    if len(payload) < 2 or payload[:2] != b"MZ":
        raise ValueError("DLL is not a Windows PE image")
    template = json.loads((ROOT / "extension.json").read_text(encoding="utf-8"))
    template["version"] = version
    template["files"][0]["sha256"] = hashlib.sha256(payload).hexdigest()
    manifest = (json.dumps(template, indent=2, ensure_ascii=False) + "\n").encode("utf-8")
    license_bytes = (ROOT / "LICENSE").read_bytes()

    out.mkdir(parents=True, exist_ok=True)
    manifest_path = out / "extension.json"
    archive_path = out / "rusthound-ce.tar.gz"
    manifest_path.write_bytes(manifest)
    with archive_path.open("wb") as raw:
        with gzip.GzipFile(fileobj=raw, mode="wb", filename="", mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                add_file(archive, "extension.json", manifest)
                add_file(archive, DLL_NAME, payload)
                add_file(archive, "LICENSE", license_bytes)
    return manifest_path, archive_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dll", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    manifest, archive = package(args.dll, args.version, args.out)
    print(manifest)
    print(archive)


if __name__ == "__main__":
    main()
