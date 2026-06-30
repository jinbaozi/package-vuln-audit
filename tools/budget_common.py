#!/usr/bin/env python3
"""Shared token estimation and packet batching for PVAS (stdlib only)."""
from __future__ import annotations

import math


def est_tokens(text: str) -> int:
    return int(math.ceil(len(text) / 3.5))


def batch_packets(entries, batch_budget: int, max_count: int) -> list[dict]:
    batches: list[dict] = []
    cur: list = []
    cur_tokens = 0
    for e in entries:
        tok = int(e.get('estimated_tokens', e.get('tokens', 0)))
        if cur and (len(cur) >= max_count or cur_tokens + tok > batch_budget):
            batches.append({
                'batch_id': f'batch-{len(batches)+1:03d}',
                'packet_count': len(cur),
                'estimated_tokens': cur_tokens,
                'packets': [x['id'] for x in cur],
            })
            cur = []
            cur_tokens = 0
        cur.append(e)
        cur_tokens += tok
    if cur:
        batches.append({
            'batch_id': f'batch-{len(batches)+1:03d}',
            'packet_count': len(cur),
            'estimated_tokens': cur_tokens,
            'packets': [x['id'] for x in cur],
        })
    return batches
