#!/usr/bin/env python3
"""Minimal YAML subset loader for core/manifest.yaml (stdlib only)."""
from __future__ import annotations

import pathlib
import re
from typing import Any


def load_manifest(path: pathlib.Path) -> dict:
    text = path.read_text(encoding='utf-8')
    doc = _parse_document(text)
    if not isinstance(doc, dict):
        raise ValueError(f'manifest root must be a mapping: {path}')
    return doc


def manifest_path(root: pathlib.Path | str) -> pathlib.Path:
    return pathlib.Path(root) / 'core' / 'manifest.yaml'


def schema_path(manifest: dict, name: str) -> pathlib.Path:
    root = manifest.get('schema_root', 'schemas')
    return pathlib.Path(root) / name


def l4_forbidden_patterns(manifest: dict) -> list[str]:
    patterns = manifest.get('l4_forbidden_patterns') or []
    return [str(p) for p in patterns]


def _strip_comment(line: str) -> str:
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '#' and not in_single and not in_double:
            return line[:i].rstrip()
    return line.rstrip()


def _line_indent(line: str) -> int:
    return len(line) - len(line.lstrip(' '))


def _split_top_level(text: str, sep: str) -> list[str]:
    parts: list[str] = []
    depth = 0
    in_single = False
    in_double = False
    start = 0
    for i, ch in enumerate(text):
        if ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "'" and not in_double:
            in_single = not in_single
        elif not in_single and not in_double:
            if ch in '{[':
                depth += 1
            elif ch in '}]':
                depth -= 1
            elif ch == sep and depth == 0:
                parts.append(text[start:i])
                start = i + 1
    parts.append(text[start:])
    return parts


def _parse_scalar(raw: str) -> Any:
    raw = raw.strip()
    if not raw or raw == '~':
        return None
    if raw == 'null':
        return None
    if raw == 'true':
        return True
    if raw == 'false':
        return False
    if raw.startswith('"') and raw.endswith('"') and len(raw) >= 2:
        return raw[1:-1]
    if raw.startswith("'") and raw.endswith("'") and len(raw) >= 2:
        return raw[1:-1]
    if raw.startswith('{') and raw.endswith('}'):
        return _parse_inline_mapping(raw[1:-1])
    if raw.startswith('[') and raw.endswith(']'):
        return _parse_inline_sequence(raw[1:-1])
    if re.fullmatch(r'-?\d+', raw):
        return int(raw)
    return raw


def _parse_inline_mapping(body: str) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for part in _split_top_level(body, ','):
        part = part.strip()
        if not part or ':' not in part:
            continue
        key, _, val = part.partition(':')
        result[key.strip()] = _parse_scalar(val.strip())
    return result


def _parse_inline_sequence(body: str) -> list[Any]:
    body = body.strip()
    if not body:
        return []
    return [_parse_scalar(part.strip()) for part in _split_top_level(body, ',') if part.strip()]


def _parse_document(text: str) -> Any:
    lines = [_strip_comment(line) for line in text.splitlines()]
    lines = [line for line in lines if line.strip()]
    if not lines:
        return {}
    value, _ = _parse_mapping(lines, 0, 0)
    return value


def _parse_mapping(lines: list[str], start: int, indent: int) -> tuple[dict[str, Any], int]:
    result: dict[str, Any] = {}
    i = start
    while i < len(lines):
        line = lines[i]
        cur_indent = _line_indent(line)
        if cur_indent < indent:
            break
        if cur_indent > indent:
            break
        stripped = line[indent:]
        if stripped.startswith('- '):
            break

        key, sep, rest = stripped.partition(':')
        if not sep:
            raise ValueError(f'invalid mapping line: {line!r}')
        key = key.strip()
        rest = rest.strip()
        if rest:
            result[key] = _parse_scalar(rest)
            i += 1
            continue

        i += 1
        if i >= len(lines):
            result[key] = {}
            break
        next_indent = _line_indent(lines[i])
        if next_indent <= indent:
            result[key] = {}
            continue
        if lines[i][next_indent:].startswith('- '):
            nested, i = _parse_sequence(lines, i, next_indent)
        else:
            nested, i = _parse_mapping(lines, i, next_indent)
        result[key] = nested
    return result, i


def _parse_sequence(lines: list[str], start: int, indent: int) -> tuple[list[Any], int]:
    result: list[Any] = []
    i = start
    while i < len(lines):
        line = lines[i]
        cur_indent = _line_indent(line)
        if cur_indent < indent:
            break
        if cur_indent > indent:
            break
        stripped = line[indent:]
        if not stripped.startswith('- '):
            break

        item_text = stripped[2:].strip()
        if not item_text:
            result.append(None)
            i += 1
            continue

        if ':' in item_text:
            key, sep, rest = item_text.partition(':')
            if sep:
                item: dict[str, Any] = {key.strip(): _parse_scalar(rest.strip())}
                i += 1
                child_indent = indent + 2
                while i < len(lines):
                    child_line = lines[i]
                    child_cur = _line_indent(child_line)
                    if child_cur < child_indent:
                        break
                    if child_cur > child_indent:
                        break
                    child_stripped = child_line[child_indent:]
                    if child_stripped.startswith('- '):
                        break
                    ck, csep, crest = child_stripped.partition(':')
                    if not csep:
                        raise ValueError(f'invalid mapping line: {child_line!r}')
                    ck = ck.strip()
                    crest = crest.strip()
                    if crest:
                        item[ck] = _parse_scalar(crest)
                        i += 1
                        continue
                    i += 1
                    if i >= len(lines):
                        item[ck] = {}
                        break
                    nested_indent = _line_indent(lines[i])
                    if lines[i][nested_indent:].startswith('- '):
                        nested, i = _parse_sequence(lines, i, nested_indent)
                    else:
                        nested, i = _parse_mapping(lines, i, nested_indent)
                    item[ck] = nested
                result.append(item)
                continue

        result.append(_parse_scalar(item_text))
        i += 1
    return result, i
