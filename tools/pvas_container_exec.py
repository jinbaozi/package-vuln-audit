#!/usr/bin/env python3
"""Subprocess runner for pvas_container.wrap_command()."""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback

import pvas_container


def _write_result_json(result: pvas_container.ContainerResult) -> None:
    path = os.environ.get("PVAS_CONTAINER_RESULT_JSON")
    if not path:
        return
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(pvas_container._result_to_dict(result), fh, indent=2, sort_keys=True)
        fh.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-json-b64", required=True)
    args = parser.parse_args(argv)

    try:
        payload = pvas_container._decode_payload(args.spec_json_b64)
        spec = pvas_container._spec_from_dict(payload["spec"])
        backend = payload.get("backend")
        result = pvas_container.run(spec, backend=backend)
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        _write_result_json(result)
        return int(result.exit_code)
    except pvas_container.SandboxUnavailable as exc:
        print(f"SandboxUnavailable: {exc}", file=sys.stderr)
        return 127
    except pvas_container.ConfigurationError as exc:
        print(f"ConfigurationError: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"pvas_container_exec unexpected error: {exc}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
