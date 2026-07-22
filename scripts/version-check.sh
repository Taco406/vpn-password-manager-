#!/usr/bin/env bash
# Version-consistency guard: the app version must be identical everywhere it's declared, and the
# changelog must have a section for it BEFORE a release can be cut (the release workflow uses the
# changelog section as the release notes, and the in-app "What's new" parses it).
# Run by `just version-check` and CI.
set -euo pipefail
cd "$(dirname "$0")/.."

tauri_v=$(python3 -c 'import json; print(json.load(open("apps/desktop/src-tauri/tauri.conf.json"))["version"])')
pkg_v=$(python3 -c 'import json; print(json.load(open("apps/desktop/package.json"))["version"])')

if [ "$tauri_v" != "$pkg_v" ]; then
    echo "VERSION DRIFT: tauri.conf.json=$tauri_v but package.json=$pkg_v — bump both together" >&2
    exit 1
fi
if ! grep -q "^## \[$tauri_v\]" CHANGELOG.md; then
    echo "CHANGELOG MISSING: no '## [$tauri_v]' section in CHANGELOG.md — add it in the same PR that bumps the version" >&2
    exit 1
fi
echo "ok: version $tauri_v consistent across tauri.conf.json, package.json, CHANGELOG.md"
