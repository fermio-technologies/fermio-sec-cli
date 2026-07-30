#!/usr/bin/env python3
"""Create a Fermio release archive and matching SHA-256 checksum."""

from __future__ import annotations

import argparse
import hashlib
import shutil
import tarfile
import tempfile
import zipfile
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--target", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", required=True, type=Path)
    return parser.parse_args()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def package(args: argparse.Namespace) -> tuple[Path, Path]:
    binary = args.binary.resolve()
    if not binary.is_file():
        raise FileNotFoundError(f"release binary does not exist: {binary}")

    repository_root = Path(__file__).resolve().parent.parent
    required_documents = [repository_root / "README.md", repository_root / "LICENSE"]
    missing = [str(path) for path in required_documents if not path.is_file()]
    if missing:
        raise FileNotFoundError(f"required release documents are missing: {', '.join(missing)}")

    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    package_name = f"fermio-sec-{args.version}-{args.target}"
    windows = "windows" in args.target
    archive = output_dir / f"{package_name}{'.zip' if windows else '.tar.gz'}"

    with tempfile.TemporaryDirectory(prefix="fermio-release-") as temporary:
        package_root = Path(temporary) / package_name
        package_root.mkdir()
        shutil.copy2(binary, package_root / binary.name)
        for document in required_documents:
            shutil.copy2(document, package_root / document.name)

        if windows:
            with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
                for path in sorted(package_root.rglob("*")):
                    if path.is_file():
                        bundle.write(path, path.relative_to(package_root.parent))
        else:
            with tarfile.open(archive, "w:gz") as bundle:
                bundle.add(package_root, arcname=package_name)

    checksum = output_dir / f"{archive.name}.sha256"
    checksum.write_text(f"{sha256(archive)}  {archive.name}\n", encoding="utf-8")
    return archive, checksum


def main() -> None:
    archive, checksum = package(parse_args())
    print(archive)
    print(checksum)


if __name__ == "__main__":
    main()
