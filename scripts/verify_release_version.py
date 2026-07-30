#!/usr/bin/env python3
"""Verify that a release tag matches Cargo metadata and the changelog."""

from __future__ import annotations

import argparse
import re
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    return parser.parse_args()


def workspace_version(cargo_toml: str) -> str:
    match = re.search(
        r"(?ms)^\[workspace\.package\]\s*.*?^version\s*=\s*\"([^\"]+)\"",
        cargo_toml,
    )
    if match is None:
        raise ValueError("workspace.package.version was not found in Cargo.toml")
    return match.group(1)


def main() -> None:
    tag = parse_args().tag
    if not tag.startswith("v") or len(tag) == 1:
        raise ValueError("release tag must start with v and contain a version")

    root = Path(__file__).resolve().parent.parent
    version = workspace_version((root / "Cargo.toml").read_text(encoding="utf-8"))
    tagged_version = tag[1:]
    if tagged_version != version:
        raise ValueError(
            f"release tag {tag!r} does not match workspace version {version!r}"
        )

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    if f"## [{version}]" not in changelog:
        raise ValueError(f"CHANGELOG.md does not contain a section for {version}")

    print(f"release version verified: {tag}")


if __name__ == "__main__":
    main()
