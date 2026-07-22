// Content script: makes NorthKey feel like a real password manager in the page.
//
//  - a small key badge appears inside the focused username/password field; clicking it opens
//    a fill menu (matching logins, an "unlock" hint when the app is locked, an empty state,
//    and a "generate password" action),
//  - on form submit with a password it offers an in-page "Save to NorthKey?" bar,
//  - the popup can ask us to fill a specific item on the active tab.
//
// It never auto-fills on load and never holds secrets: every credential is fetched from the
// desktop only on an explicit user gesture, and the desktop re-checks the page origin before
// releasing any field. All UI lives in a shadow-root overlay and is styled via the CSSOM so a
// site's Content-Security-Policy can't block it.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const runtime = (globalThis as any).chrome?.runtime;

const BRAND = "#22d3ee";
const PANEL_BG = "#0f141c";
const PANEL_BORDER = "#28323f";
const TEXT = "#e6edf3";
const MUTED = "#9aa7b4";

function pageOrigin(): string {
  return location.origin;
}

// Never operate inside a cross-origin iframe.
function inCrossOriginFrame(): boolean {
  try {
    return window.top !== window.self && window.top!.location.origin !== location.origin;
  } catch {
    return true; // access denied ⇒ cross-origin
  }
}

// ---------------------------------------------------------------------------
// login-field detection
// ---------------------------------------------------------------------------

interface LoginFields {
  username?: HTMLInputElement;
  password?: HTMLInputElement;
}

function isVisible(el: HTMLElement): boolean {
  const r = el.getBoundingClientRect();
  return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== "hidden";
}

/// The password field nearest a given element, and the text/email field just before it.
function fieldsFor(anchor: HTMLInputElement): LoginFields {
  const form = anchor.form ?? document;
  const password =
    (anchor.type === "password" ? anchor : undefined) ??
    form.querySelector<HTMLInputElement>('input[type="password"]') ??
    undefined;
  let username: HTMLInputElement | undefined;
  const inputs = Array.from(form.querySelectorAll<HTMLInputElement>("input"));
  if (password) {
    const idx = inputs.indexOf(password);
    username =
      inputs
        .slice(0, idx)
        .reverse()
        .find((i) => ["text", "email", "tel"].includes(i.type) || i.autocomplete === "username") ??
      form.querySelector<HTMLInputElement>('input[autocomplete="username"], input[type="email"]') ??
      undefined;
  } else if (anchor.type !== "password") {
    username = anchor;
  }
  return { username, password };
}

/// True if an input participates in a login (has, or sits beside, a password field).
function isLoginInput(el: EventTarget | null): el is HTMLInputElement {
  if (!(el instanceof HTMLInputElement)) return false;
  if (el.type === "password") return true;
  if (!["text", "email", "tel"].includes(el.type) && el.autocomplete !== "username") return false;
  const { password } = fieldsFor(el);
  return !!password;
}

function setValue(el: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter?.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

// ---------------------------------------------------------------------------
// shadow-root overlay (isolated from page CSS, CSP-safe inline CSSOM styling)
// ---------------------------------------------------------------------------

let overlay: ShadowRoot | null = null;
function ui(): ShadowRoot {
  if (overlay) return overlay;
  const host = document.createElement("div");
  host.id = "sentinel-autofill-overlay";
  host.style.cssText =
    "position:fixed;inset:0;z-index:2147483647;pointer-events:none;border:0;margin:0;padding:0;";
  (document.documentElement || document.body).appendChild(host);
  overlay = host.attachShadow({ mode: "closed" });
  return overlay;
}

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  css: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  node.style.cssText = css;
  if (text !== undefined) node.textContent = text;
  return node;
}

const KEY_SVG =
  "data:image/svg+xml;utf8," +
  encodeURIComponent(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="${BRAND}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="7.5" cy="15.5" r="4.5"/><path d="m10.7 12.3 8.3-8.3"/><path d="m16 6 3 3"/><path d="m14 8 2.5 2.5"/></svg>`,
  );

// ---------------------------------------------------------------------------
// field badge (the clickable key icon inside the focused login field)
// ---------------------------------------------------------------------------

let badge: HTMLButtonElement | null = null;
let badgeAnchor: HTMLInputElement | null = null;

function showBadge(anchor: HTMLInputElement) {
  badgeAnchor = anchor;
  if (!badge) {
    badge = el(
      "button",
      "position:fixed;width:22px;height:22px;padding:0;border:0;border-radius:6px;" +
        "background:#0b0f16;box-shadow:0 0 0 1px " +
        PANEL_BORDER +
        ";cursor:pointer;pointer-events:auto;display:grid;place-items:center;opacity:.9;",
    );
    const img = el("img", "width:15px;height:15px;");
    (img as HTMLImageElement).src = KEY_SVG;
    badge.appendChild(img);
    badge.title = "Fill with NorthKey";
    badge.addEventListener("mousedown", (e) => e.preventDefault()); // keep field focus
    badge.addEventListener("click", (e) => {
      e.preventDefault();
      e.stopPropagation();
      openMenu(anchor);
    });
    ui().appendChild(badge);
  }
  positionBadge();
}

function positionBadge() {
  if (!badge || !badgeAnchor) return;
  if (!document.contains(badgeAnchor) || !isVisible(badgeAnchor)) {
    hideBadge();
    return;
  }
  const r = badgeAnchor.getBoundingClientRect();
  badge.style.left = `${r.right - 26}px`;
  badge.style.top = `${r.top + (r.height - 22) / 2}px`;
  badge.style.display = "grid";
}

function hideBadge() {
  badge?.remove();
  badge = null;
  badgeAnchor = null;
}

// ---------------------------------------------------------------------------
// fill menu
// ---------------------------------------------------------------------------

interface Item {
  id: string;
  title: string;
  username?: string;
}

let menu: HTMLDivElement | null = null;

function closeMenu() {
  menu?.remove();
  menu = null;
}

function panel(anchor: HTMLElement): HTMLDivElement {
  closeMenu();
  const r = anchor.getBoundingClientRect();
  const box = el(
    "div",
    `position:fixed;left:${Math.min(r.left, window.innerWidth - 280)}px;top:${r.bottom + 6}px;` +
      `width:264px;background:${PANEL_BG};color:${TEXT};border:1px solid ${PANEL_BORDER};` +
      "border-radius:12px;padding:6px;pointer-events:auto;box-shadow:0 12px 32px rgba(0,0,0,.55);" +
      'font:13px system-ui,-apple-system,"Segoe UI",sans-serif;',
  );
  const head = el(
    "div",
    `display:flex;align-items:center;gap:6px;padding:6px 8px 8px;color:${MUTED};font-size:11px;` +
      "letter-spacing:.04em;text-transform:uppercase;",
    "NorthKey",
  );
  box.appendChild(head);
  menu = box;
  ui().appendChild(box);
  const onDoc = (e: MouseEvent) => {
    if (menu && !e.composedPath().includes(menu) && e.target !== badge) closeMenu();
  };
  setTimeout(() => document.addEventListener("mousedown", onDoc, { once: true }), 0);
  return box;
}

function row(label: string, sub: string | undefined, onClick: () => void): HTMLButtonElement {
  const b = el(
    "button",
    "display:flex;flex-direction:column;align-items:flex-start;gap:2px;width:100%;text-align:left;" +
      `background:none;border:0;color:${TEXT};padding:8px 9px;border-radius:8px;cursor:pointer;`,
  );
  b.appendChild(el("span", "font-weight:500;", label));
  if (sub) b.appendChild(el("span", `font-size:11px;color:${MUTED};`, sub));
  b.addEventListener("mouseenter", () => (b.style.background = "#22d3ee1a"));
  b.addEventListener("mouseleave", () => (b.style.background = "none"));
  b.addEventListener("mousedown", (e) => e.preventDefault());
  b.addEventListener("click", (e) => {
    e.preventDefault();
    onClick();
  });
  return b;
}

async function openMenu(anchor: HTMLInputElement) {
  const box = panel(anchor);
  const loading = el("div", `padding:10px;color:${MUTED};`, "Loading…");
  box.appendChild(loading);

  const res = await sendBg("search", { query: "", origin: pageOrigin() });
  if (menu !== box) return; // superseded
  loading.remove();

  const locked = res?.err?.code === "LOCKED";
  const items = (res?.payload as { items?: Item[] })?.items ?? [];

  if (locked) {
    box.appendChild(
      row("Unlock NorthKey to fill", "Open the desktop app and unlock your vault", () => {
        closeMenu();
      }),
    );
  } else if (items.length === 0) {
    box.appendChild(
      el("div", `padding:6px 9px;color:${MUTED};`, "No saved logins for this site."),
    );
  } else {
    for (const it of items) {
      box.appendChild(row(it.title, it.username || "—", () => void fillFrom(anchor, it.id)));
    }
  }

  // Generator is always available (touches no secrets) — offer it on the password field.
  if (!locked) {
    const div = el("div", `height:1px;background:${PANEL_BORDER};margin:6px 4px;`);
    box.appendChild(div);
    box.appendChild(
      row("Generate password", "Strong, unique — fills the box", () => void generateInto(anchor)),
    );
  }
}

async function fillFrom(anchor: HTMLInputElement, id: string) {
  const res = await sendBg("fields", {
    id,
    fields: ["username", "password"],
    origin: pageOrigin(),
    reason: "autofill",
  });
  closeMenu();
  if (res?.err) return;
  const fields = (res?.payload as { fields?: Record<string, string> })?.fields ?? {};
  const { username, password } = fieldsFor(anchor);
  if (username && fields.username) setValue(username, fields.username);
  if (password && fields.password) {
    setValue(password, fields.password);
    lastFilled = { user: fields.username ?? "", pass: fields.password };
  }
}

async function generateInto(anchor: HTMLInputElement) {
  const res = await sendBg("generate", {});
  closeMenu();
  const pw = (res?.payload as { password?: string })?.password;
  if (!pw) return;
  const { password } = fieldsFor(anchor);
  const target = password ?? (anchor.type === "password" ? anchor : undefined);
  if (target) setValue(target, pw);
}

// ---------------------------------------------------------------------------
// save-on-submit bar
// ---------------------------------------------------------------------------

let lastFilled: { user: string; pass: string } | null = null;
const offered = new Set<string>();
let saveBar: HTMLDivElement | null = null;

function showSaveBar(username: string, password: string, title: string) {
  const key = `${pageOrigin()}|${username}`;
  if (offered.has(key)) return;
  // Don't nag when the submitted creds are exactly what we just autofilled.
  if (lastFilled && lastFilled.user === username && lastFilled.pass === password) return;
  offered.add(key);
  saveBar?.remove();

  const bar = el(
    "div",
    `position:fixed;right:18px;bottom:18px;width:320px;background:${PANEL_BG};color:${TEXT};` +
      `border:1px solid ${PANEL_BORDER};border-radius:14px;padding:14px 14px 12px;pointer-events:auto;` +
      "box-shadow:0 16px 40px rgba(0,0,0,.6);font:13px system-ui,-apple-system,sans-serif;",
  );
  const top = el("div", "display:flex;align-items:center;gap:8px;margin-bottom:4px;");
  const icon = el("img", "width:16px;height:16px;");
  (icon as HTMLImageElement).src = KEY_SVG;
  top.appendChild(icon);
  top.appendChild(el("span", "font-weight:600;", "Save password to NorthKey?"));
  bar.appendChild(top);
  bar.appendChild(
    el(
      "div",
      `color:${MUTED};margin:2px 0 12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;`,
      `${username || "(no username)"} · ${host(pageOrigin())}`,
    ),
  );

  const actions = el("div", "display:flex;gap:8px;justify-content:flex-end;");
  const not = el(
    "button",
    `background:none;border:1px solid ${PANEL_BORDER};color:${MUTED};border-radius:8px;` +
      "padding:7px 12px;cursor:pointer;",
    "Not now",
  );
  not.addEventListener("click", () => saveBar?.remove());
  const save = el(
    "button",
    `background:${BRAND};border:0;color:#04121a;font-weight:600;border-radius:8px;` +
      "padding:7px 14px;cursor:pointer;",
    "Save",
  );
  save.addEventListener("click", async () => {
    save.textContent = "Saving…";
    const res = await sendBg("save_candidate", {
      origin: pageOrigin(),
      username,
      password,
      title,
    });
    if (res?.err) {
      const msg = res.err.code === "LOCKED" ? "Unlock the app first" : "Couldn't save";
      save.textContent = msg;
      save.style.background = "#3a2330";
      save.style.color = TEXT;
      return;
    }
    const action = (res?.payload as { action?: string })?.action;
    save.textContent = action === "updated" ? "Updated ✓" : "Saved ✓";
    save.style.background = "#173a2a";
    save.style.color = "#8ff0bf";
    not.remove();
    setTimeout(() => saveBar?.remove(), 1400);
  });
  actions.appendChild(not);
  actions.appendChild(save);
  bar.appendChild(actions);

  ui().appendChild(bar);
  saveBar = bar;
  setTimeout(() => {
    if (saveBar === bar) bar.remove();
  }, 20000);
}

function host(origin: string): string {
  try {
    return new URL(origin).host;
  } catch {
    return origin;
  }
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------

function onFocusIn(e: FocusEvent) {
  if (isLoginInput(e.target)) showBadge(e.target as HTMLInputElement);
}
function onFocusOut() {
  // Hide the badge unless focus moved to it or its menu; small delay for the click to register.
  setTimeout(() => {
    const a = document.activeElement;
    if (a !== badgeAnchor && !menu) hideBadge();
  }, 150);
}

function watchSubmit() {
  const capture = (form: HTMLFormElement | null, fallbackPw?: HTMLInputElement) => {
    const password = form?.querySelector<HTMLInputElement>('input[type="password"]') ?? fallbackPw;
    if (!password || !password.value) return;
    const { username } = fieldsFor(password);
    showSaveBar(username?.value ?? "", password.value, document.title || location.hostname);
  };
  document.addEventListener("submit", (e) => capture(e.target as HTMLFormElement), true);
  // Many SPA logins never fire a real submit — also offer on the Enter key / button clicks
  // that leave a filled password behind.
  document.addEventListener(
    "keydown",
    (e) => {
      if (e.key !== "Enter") return;
      const t = e.target;
      if (t instanceof HTMLInputElement && (t.type === "password" || isLoginInput(t))) {
        setTimeout(() => capture(t.form, t.type === "password" ? t : undefined), 0);
      }
    },
    true,
  );
}

function reposition() {
  positionBadge();
}

// Popup → content: fill a chosen item on this tab.
runtime?.onMessage?.addListener(
  (req: { cmd?: string; id?: string }, _s: unknown, send: (r: unknown) => void) => {
    if (req?.cmd === "fill" && req.id) {
      const anchor =
        (document.activeElement instanceof HTMLInputElement ? document.activeElement : null) ??
        document.querySelector<HTMLInputElement>('input[type="password"]') ??
        document.querySelector<HTMLInputElement>("input");
      if (anchor) void fillFrom(anchor, req.id);
      send({ ok: true });
    }
    return false;
  },
);

interface BgReply {
  ok?: boolean;
  payload?: unknown;
  err?: { code: string; message: string };
}
function sendBg(cmd: string, payload: unknown): Promise<BgReply | undefined> {
  return new Promise((resolve) => {
    try {
      runtime.sendMessage({ cmd, payload }, (r: BgReply) => resolve(r));
    } catch {
      resolve(undefined);
    }
  });
}

// Passkeys: bridge the page-context WebAuthn shim (inpage.js, MAIN world) to the desktop.
// The requesting origin is set HERE from location.origin — never trusted from the page — so a
// page can't ask the desktop to act for another site. Runs in every frame (no autofill UI here).
window.addEventListener("message", (ev: MessageEvent) => {
  if (ev.source !== window) return;
  const d = ev.data as
    | { source?: string; kind?: string; reqId?: string; payload?: Record<string, unknown> }
    | null;
  if (!d || d.source !== "northkey-passkey" || typeof d.reqId !== "string") return;
  const cmd = d.kind === "register" ? "passkey_register" : d.kind === "assert" ? "passkey_assert" : null;
  if (!cmd) return;
  const payload = { ...(d.payload ?? {}), origin: location.origin };
  void sendBg(cmd, payload).then((reply) => {
    window.postMessage(
      {
        source: "northkey-passkey-reply",
        reqId: d.reqId,
        ok: reply?.ok === true,
        payload: reply?.payload,
        err: reply?.err,
      },
      location.origin,
    );
  });
});

if (!inCrossOriginFrame()) {
  document.addEventListener("focusin", onFocusIn, true);
  document.addEventListener("focusout", onFocusOut, true);
  window.addEventListener("scroll", reposition, true);
  window.addEventListener("resize", reposition, true);
  watchSubmit();
}

export {};
