#!/usr/bin/env python3
"""Shared JSON I/O helpers for PVAS tools (stdlib only)."""
from __future__ import annotations

import json
import pathlib
from typing import Any


def load_json(
    path: pathlib.Path | str | None,
    default: Any = None,
    *,
    required: bool = False,
) -> Any:
    p = pathlib.Path(path) if path else None
    if not p or not p.exists():
        if required:
            raise FileNotFoundError(f'missing required JSON: {p}')
        return default
    try:
        return json.loads(p.read_text())
    except json.JSONDecodeError:
        if required:
            raise
        return default


def write_json(
    path: pathlib.Path | str,
    data: Any,
    *,
    indent: int = 2,
    ensure_ascii: bool = False,
) -> None:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=indent, ensure_ascii=ensure_ascii))


def findings_list(data: Any) -> list[dict]:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get('findings', [])
    return []


def load_findings(path: pathlib.Path | str) -> list[dict]:
    data = load_json(path, default={}, required=True)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        if 'findings' in data:
            return data['findings']
        if 'id' in data:
            return [data]
    return []


def corr_map(data: Any) -> dict[str, dict]:
    if not isinstance(data, dict):
        return {}
    return {c.get('finding_id'): c for c in data.get('correlations', [])}
