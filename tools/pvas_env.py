#!/usr/bin/env python3
"""Shared PVAS environment flag parsing (stdlib only)."""
from __future__ import annotations

import os


def env_flag(name: str, default: bool = False) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.lower() in {'1', 'true', 'yes', 'on'}
