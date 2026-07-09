#!/usr/bin/env python3
"""Deduplicate Python wheels in offline-bundle/python/wheels/.

Multiple versions of the same distribution cause `pip install --no-index`
to fail with "ResolutionImpossible" because pip cannot satisfy both version
constraints at once. This script uses PEP 503-style name extraction to
identify the distribution name of each wheel (everything before the first
component starting with a digit) and keeps only the lexicographically-latest
version.

Usage:
    python3 dedupe-wheels.py [WHEELS_DIR]

Default WHEELS_DIR is offline-bundle/python/wheels (relative to skill root).

Exit code 0 on success. Never fails; even with no duplicates it is a no-op.
"""
from __future__ import annotations

import glob
import os
import sys
from collections import defaultdict


def wheel_name(filename: str) -> str:
    """Extract PEP 503 distribution name from a wheel filename.

    Wheel filename format: {distribution}-{version}(-...){.whl}
    The distribution name is everything before the first segment that
    starts with a digit. This handles:
      - cppcheck-1.5.1-py3-none-any.whl       -> "cppcheck"
      - importlib_metadata-9.0.0-py3-none-any.whl -> "importlib-metadata"
      - uvicorn-0.50.2-py3-none-any.whl       -> "uvicorn"
      - libiberty_hashtab-1.0-py3-none-any.whl -> "libiberty-hashtab"
    """
    base = os.path.basename(filename)
    if not base.endswith(".whl"):
        return ""
    parts = base[:-4].split("-")
    for i, p in enumerate(parts):
        if p and p[0].isdigit():
            return "-".join(parts[:i]).lower().replace("_", "-")
    return "-".join(parts).lower().replace("_", "-")


def main() -> int:
    skill_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    wheels_dir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        skill_root, "offline-bundle", "python", "wheels"
    )

    if not os.path.isdir(wheels_dir):
        print(f"[dedupe-wheels] WARN: {wheels_dir} does not exist; skipping")
        return 0

    wheels = sorted(glob.glob(os.path.join(wheels_dir, "*.whl")))
    groups: dict[str, list[str]] = defaultdict(list)
    for w in wheels:
        n = wheel_name(w)
        if n:
            groups[n].append(w)

    removed = 0
    for name, files in groups.items():
        if len(files) <= 1:
            continue
        files.sort()
        # Keep the last (newest) version; remove the rest
        for f in files[:-1]:
            print(f"[dedupe-wheels] remove {os.path.basename(f)} (keeping {os.path.basename(files[-1])})")
            os.remove(f)
            removed += 1
    print(f"[dedupe-wheels] processed {len(wheels)} wheels in {wheels_dir}; removed {removed} duplicates")
    return 0


if __name__ == "__main__":
    sys.exit(main())