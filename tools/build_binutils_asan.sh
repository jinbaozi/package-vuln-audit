#!/usr/bin/env bash
set -euo pipefail

SRC="${1:-.}"
BUILD="${2:-build-asan}"
mkdir -p "$BUILD"
cd "$BUILD"

CFLAGS="${CFLAGS:--O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer}"
CXXFLAGS="${CXXFLAGS:--O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer}"
LDFLAGS="${LDFLAGS:--fsanitize=address,undefined}"
export CFLAGS CXXFLAGS LDFLAGS

"$SRC/configure" --disable-werror --enable-targets=all
make -j"${JOBS:-$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)}"
