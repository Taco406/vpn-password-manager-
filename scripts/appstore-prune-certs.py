#!/usr/bin/env python3
"""Revoke stale Apple *distribution* certificates so a cloud-signed build always has a free slot.

Why this exists
---------------
The iOS TestFlight workflow signs with `xcodebuild -allowProvisioningUpdates` ("cloud signing").
Every CI run happens on a throwaway macOS runner that has no access to the private key of the
certificate the previous run used, so Apple mints a BRAND-NEW distribution certificate each time.
Apple also caps how many distribution certificates an account may hold. After a couple of releases
the cap is reached and every later build dies at the archive step with:

    Choose a certificate to revoke. Your account has reached the maximum number of certificates.
    No profiles for 'com.northkey.app' were found ...

The failure is silent from the user's side — the release publishes fine, the desktop updates, and
the phone just never receives a build. That is exactly how this repo shipped 1.58 and 1.59 to the
desktop while the iPhone sat on 1.57. Revoking one certificate by hand "fixes" it for precisely one
build, because that build immediately consumes the slot again.

So: before archiving, revoke the distribution certificates this pipeline created. This is safe —
a distribution certificate is only needed to SIGN a new upload. Builds already delivered to
TestFlight or the App Store remain valid and installable after their signing certificate is
revoked, and the keys being revoked live on runners that no longer exist.

Requires the same three App Store Connect secrets the workflow already uses:
APPSTORE_API_KEY_ID, APPSTORE_API_ISSUER_ID, APPSTORE_API_PRIVATE_KEY.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request

try:
    import jwt  # PyJWT, with the `cryptography` backend for ES256
except ImportError:  # pragma: no cover - the workflow installs this first
    sys.exit("pyjwt[crypto] is required: pip3 install 'pyjwt[crypto]'")

API = "https://api.appstoreconnect.apple.com/v1"

# Certificate types that occupy the distribution cap. Development certs are left alone — they
# have their own (separate) limit and nothing here creates them.
DISTRIBUTION_TYPES = {
    "DISTRIBUTION",
    "IOS_DISTRIBUTION",
    "MAC_APP_DISTRIBUTION",
    "MAC_INSTALLER_DISTRIBUTION",
}


def make_token(key_id: str, issuer_id: str, private_key: str) -> str:
    """A short-lived ES256 JWT — the App Store Connect API's auth scheme."""
    now = int(time.time())
    return jwt.encode(
        {"iss": issuer_id, "iat": now, "exp": now + 600, "aud": "appstoreconnect-v1"},
        private_key,
        algorithm="ES256",
        headers={"kid": key_id, "typ": "JWT"},
    )


def request(method: str, path: str, token: str):
    req = urllib.request.Request(f"{API}{path}", method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode()
            return resp.status, (json.loads(body) if body.strip() else {})
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:400]
        return e.code, {"error": detail}


def main() -> int:
    key_id = os.environ.get("KEY_ID", "").strip()
    issuer_id = os.environ.get("ISSUER", "").strip()
    private_key = os.environ.get("P8", "")
    if not (key_id and issuer_id and private_key.strip()):
        # The workflow already hard-fails on missing secrets; don't mask that error here.
        print("prune-certs: App Store Connect secrets not set — skipping.")
        return 0

    token = make_token(key_id, issuer_id, private_key)

    status, body = request("GET", "/certificates?limit=200", token)
    if status != 200:
        # Never block the build on a pruning failure: the archive step reports the real
        # signing error, and a spurious failure here would be its own silent-delivery bug.
        print(f"prune-certs: could not list certificates (HTTP {status}): {body.get('error', '')}")
        return 0

    certs = body.get("data", [])
    distribution = [
        c for c in certs if (c.get("attributes") or {}).get("certificateType") in DISTRIBUTION_TYPES
    ]
    print(f"prune-certs: {len(certs)} certificate(s) on the account, {len(distribution)} distribution.")

    if not distribution:
        print("prune-certs: nothing to revoke — cloud signing will mint a fresh certificate.")
        return 0

    revoked = 0
    for cert in distribution:
        attrs = cert.get("attributes") or {}
        name = attrs.get("name") or attrs.get("certificateType") or "certificate"
        expires = attrs.get("expirationDate", "?")
        status, body = request("DELETE", f"/certificates/{cert['id']}", token)
        if status in (200, 204):
            revoked += 1
            print(f"prune-certs: revoked {name} (expires {expires})")
        else:
            print(f"prune-certs: could NOT revoke {name} (HTTP {status}): {body.get('error', '')}")

    print(f"prune-certs: revoked {revoked}/{len(distribution)}; a fresh one is minted during archive.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
