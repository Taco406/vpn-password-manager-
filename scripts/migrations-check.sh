#!/usr/bin/env bash
# Shipped migrations are append-only. The server applies migrations with sqlx's Migrator, which
# records a checksum per applied file — if a released migration file is EDITED, every deployed
# server hits a checksum mismatch at next boot and crash-loops (with SSH masked, that means
# destroy+redeploy). CI can't catch this naturally (it always starts from a fresh DB), so this
# manifest is the tripwire.
#
#   verify (default): every manifest entry must match its file byte-for-byte; every migration
#                     file must be listed. Fails loudly otherwise.
#   --update:         append NEW migration files to the manifest. Never rewrites existing
#                     entries — an entry that no longer matches means the file was edited,
#                     which is exactly the bug this exists to catch.
set -euo pipefail
cd "$(dirname "$0")/.."

MANIFEST=services/api/migrations/.checksums
MIGRATIONS=(services/api/migrations/[0-9]*.sql)

sha() { sha256sum "$1" | cut -d' ' -f1; }

if [ "${1:-}" = "--update" ]; then
    touch "$MANIFEST"
    for f in "${MIGRATIONS[@]}"; do
        name=$(basename "$f")
        if ! grep -q " $name\$" "$MANIFEST"; then
            echo "$(sha "$f") $name" >> "$MANIFEST"
            echo "added $name"
        fi
    done
    exit 0
fi

[ -f "$MANIFEST" ] || { echo "manifest $MANIFEST missing — run scripts/migrations-check.sh --update" >&2; exit 1; }

fail=0
while read -r want name; do
    f="services/api/migrations/$name"
    if [ ! -f "$f" ]; then
        echo "MIGRATION DELETED: $name is in the manifest but gone — shipped migrations must never be removed" >&2
        fail=1
    elif [ "$(sha "$f")" != "$want" ]; then
        echo "MIGRATION EDITED: $name no longer matches its shipped checksum — deployed servers will crash-loop on boot. Add a NEW migration instead." >&2
        fail=1
    fi
done < "$MANIFEST"

for f in "${MIGRATIONS[@]}"; do
    name=$(basename "$f")
    if ! grep -q " $name\$" "$MANIFEST"; then
        echo "NEW MIGRATION UNLISTED: $name — run scripts/migrations-check.sh --update and commit the manifest" >&2
        fail=1
    fi
done

[ "$fail" -eq 0 ] && echo "ok: $(wc -l < "$MANIFEST") shipped migrations unchanged"
exit "$fail"
