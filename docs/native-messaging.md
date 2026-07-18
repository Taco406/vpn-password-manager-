# Native messaging protocol (Chrome ⇄ desktop)

Both hops (Chrome ⇄ `sentinel-nm-host`, and host ⇄ desktop over the local IPC socket)
use the same wire format: a **u32 little-endian length prefix** followed by UTF-8 JSON
of an `NmEnvelope`, capped at **1 MiB** per frame.

Types live in `crates/core/nm/protocol.rs` and are mirrored in
`packages/shared/src/nmProtocol.ts`; golden tests keep the wire strings in lockstep.

## Envelope

```json
{ "id": "uuid", "type": "vault.search", "ok": true, "payload": { ... }, "err": null }
```

## Message types

| type | direction | purpose |
|---|---|---|
| `hello` | ext → desktop | handshake; returns `{caps, appVersion, locked}` |
| `status.subscribe` / `status.event` | both | lock state + VPN pill (no secrets) |
| `vault.search` | ext → desktop | `{query, origin}` → `{items: [...]}` (no passwords) |
| `vault.fields.get` | ext → desktop | `{id, fields, origin, reason}` → decrypted fields |
| `vault.totp.get` | ext → desktop | `{id}` → `{code, remainingMs}` |
| `vault.generate` | ext → desktop | password generation |
| `vault.save_candidate` | ext → desktop | offer to save on submit |
| `lock.event` | desktop → ext | lock state changed |

## Trust boundary

The **desktop** is the authority. On every `vault.*` request it re-checks the page
`origin` against each item's saved URL (`vault::session::origin_matches`) before
releasing any field. While the desktop is locked, every `vault.*` request returns
`err.code = "LOCKED"` with no payload, and the extension caches zero credential data
(asserted by the host test `vault_requests_are_locked_without_desktop`).

## Autofill matching (extension side, mirrors the Rust check)

1. https-saved never fills on http (no downgrade);
2. non-default ports must match exactly;
3. `host` mode = exact host; `domain` mode = registrable-domain equality (PSL);
4. never fill inside a cross-origin iframe;
5. fill only on an explicit user gesture (never on load);
6. ambiguous multi-match ranked host-exact > subdomain-depth > recency.

## Installing the host manifest

`apps/extension/host/com.sentinel.host.json.tmpl` is installed by the desktop app (or
`just nm-install`) with `__SENTINEL_NM_HOST_PATH__` and `__SENTINEL_EXTENSION_ID__`
filled in, to the browser's native-messaging-hosts directory.
