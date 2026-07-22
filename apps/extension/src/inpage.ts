// Page-context (MAIN world) WebAuthn shim. Overrides navigator.credentials.create/get so a
// NorthKey passkey can register with, or sign in to, a website. It talks to the isolated
// content script via window.postMessage (MAIN world can't use chrome.*), which relays to the
// desktop over native messaging.
//
// Design principle: NON-HIJACKING. Every decline, miss, lock, timeout, or error falls through
// to the browser's own authenticators, so existing security keys and platform passkeys keep
// working untouched. NorthKey only handles a request when the user opts in AND the desktop
// actually has (or creates) a matching credential.

(() => {
  // Top frame only — the content-script relay runs there, and it keeps WebAuthn in subframes
  // on the browser's own authenticators (no relay, no hang).
  if (window.top !== window) return;

  const creds = navigator.credentials as CredentialsContainer | undefined;
  if (!creds || typeof creds.create !== "function" || typeof creds.get !== "function") return;

  const origCreate = creds.create.bind(creds);
  const origGet = creds.get.bind(creds);

  // Pending request bookkeeping (reqId → resolver).
  const waiters = new Map<string, (v: Reply) => void>();
  let seq = 0;

  interface Reply {
    ok: boolean;
    payload?: Record<string, unknown>;
    err?: { code: string; message: string };
    timeout?: boolean;
  }

  window.addEventListener("message", (ev: MessageEvent) => {
    if (ev.source !== window) return;
    const d = ev.data as { source?: string; reqId?: string } & Reply;
    if (!d || d.source !== "northkey-passkey-reply" || typeof d.reqId !== "string") return;
    const resolve = waiters.get(d.reqId);
    if (resolve) {
      waiters.delete(d.reqId);
      resolve(d);
    }
  });

  function ask(kind: "register" | "assert", payload: Record<string, unknown>): Promise<Reply> {
    return new Promise((resolve) => {
      const reqId = `nk-${++seq}-${Date.now()}`;
      waiters.set(reqId, resolve);
      window.postMessage({ source: "northkey-passkey", kind, reqId, payload }, location.origin);
      window.setTimeout(() => {
        if (waiters.has(reqId)) {
          waiters.delete(reqId);
          resolve({ ok: false, timeout: true });
        }
      }, 60_000);
    });
  }

  // --- base64url + buffer helpers ---
  function view(v: BufferSource): Uint8Array {
    if (v instanceof ArrayBuffer) return new Uint8Array(v);
    const b = v as ArrayBufferView;
    return new Uint8Array(b.buffer, b.byteOffset, b.byteLength);
  }
  function b64uEnc(v: BufferSource): string {
    const b = view(v);
    let s = "";
    for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function b64uDec(s: string): Uint8Array {
    const p = s.replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(p + "=".repeat((4 - (p.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function clientDataJSON(type: "webauthn.create" | "webauthn.get", challenge: BufferSource): string {
    return JSON.stringify({
      type,
      challenge: b64uEnc(challenge),
      origin: location.origin,
      crossOrigin: false,
    });
  }

  // Build a PublicKeyCredential-shaped object. We can't `new PublicKeyCredential()`, so this is a
  // structural stand-in; most relying-party libraries read these fields directly.
  function withProto(cred: Record<string, unknown>): Credential {
    const proto = (window as unknown as { PublicKeyCredential?: { prototype: object } })
      .PublicKeyCredential?.prototype;
    if (proto) {
      try {
        Object.setPrototypeOf(cred, proto);
      } catch {
        /* prototype set is best-effort */
      }
    }
    return cred as unknown as Credential;
  }

  creds.create = async function create(
    options?: CredentialCreationOptions,
  ): Promise<Credential | null> {
    const pk = options?.publicKey;
    if (!pk) return origCreate(options);
    try {
      const rpId = pk.rp?.id || location.hostname;
      const consent = window.confirm(
        `Create a passkey for "${rpId}" in NorthKey?\n\nOK = save to NorthKey    ·    Cancel = use this device`,
      );
      if (!consent) return origCreate(options);

      const cdj = clientDataJSON("webauthn.create", pk.challenge as BufferSource);
      const user = pk.user as PublicKeyCredentialUserEntity;
      const reply = await ask("register", {
        rpId,
        rpName: pk.rp?.name,
        userName: user?.name ?? "",
        userDisplayName: user?.displayName,
        userHandleB64u: b64uEnc(user.id as BufferSource),
      });
      const p = reply.payload as
        | { credentialIdB64u: string; attestationObjectB64u: string; authenticatorDataB64u: string }
        | undefined;
      if (!reply.ok || !p) return origCreate(options);

      const rawId = b64uDec(p.credentialIdB64u);
      const attestationObject = b64uDec(p.attestationObjectB64u);
      const authData = b64uDec(p.authenticatorDataB64u);
      const clientDataBytes = new TextEncoder().encode(cdj);
      return withProto({
        id: p.credentialIdB64u,
        rawId: rawId.buffer,
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: clientDataBytes.buffer,
          attestationObject: attestationObject.buffer,
          getAuthenticatorData: () => authData.buffer,
          getPublicKey: () => null,
          getPublicKeyAlgorithm: () => -7,
          getTransports: () => ["internal", "hybrid"],
        },
        getClientExtensionResults: () => ({}),
      });
    } catch {
      return origCreate(options);
    }
  };

  creds.get = async function get(options?: CredentialRequestOptions): Promise<Credential | null> {
    const pk = options?.publicKey;
    if (!pk) return origGet(options);
    try {
      const rpId = pk.rpId || location.hostname;
      // Ask up front so we never sign (and never bump the counter) without the user's intent.
      const consent = window.confirm(`Sign in to "${rpId}" with your NorthKey passkey?`);
      if (!consent) return origGet(options);

      const cdj = clientDataJSON("webauthn.get", pk.challenge as BufferSource);
      const allow = (pk.allowCredentials ?? []).map((c) => b64uEnc(c.id as BufferSource));
      const reply = await ask("assert", {
        rpId,
        clientDataJson: cdj,
        allowCredentialIdsB64u: allow,
      });
      const p = reply.payload as
        | {
            credentialIdB64u: string;
            authenticatorDataB64u: string;
            signatureB64u: string;
            userHandleB64u: string;
          }
        | undefined;
      if (!reply.ok || !p) return origGet(options); // no NorthKey passkey → let the platform try

      const clientDataBytes = new TextEncoder().encode(cdj);
      const userHandle = p.userHandleB64u ? b64uDec(p.userHandleB64u).buffer : null;
      return withProto({
        id: p.credentialIdB64u,
        rawId: b64uDec(p.credentialIdB64u).buffer,
        type: "public-key",
        authenticatorAttachment: "platform",
        response: {
          clientDataJSON: clientDataBytes.buffer,
          authenticatorData: b64uDec(p.authenticatorDataB64u).buffer,
          signature: b64uDec(p.signatureB64u).buffer,
          userHandle,
        },
        getClientExtensionResults: () => ({}),
      });
    } catch {
      return origGet(options);
    }
  };

  // Advertise a platform authenticator so sites offer the passkey path.
  const PKC = (window as unknown as { PublicKeyCredential?: Record<string, unknown> })
    .PublicKeyCredential;
  if (PKC) {
    try {
      PKC.isUserVerifyingPlatformAuthenticatorAvailable = () => Promise.resolve(true);
    } catch {
      /* leave the native implementation in place */
    }
  }
})();
