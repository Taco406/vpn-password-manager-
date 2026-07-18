// Content script: detects login forms, offers a fill menu on an explicit user gesture
// (never auto-fill-on-load), and offers to save credentials on submit. Domain matching
// is enforced by the desktop before any field is released; this script only requests.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const runtime = (globalThis as any).chrome?.runtime;

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

function findLoginFields(): { username?: HTMLInputElement; password?: HTMLInputElement } {
  const password = document.querySelector<HTMLInputElement>('input[type="password"]') ?? undefined;
  let username: HTMLInputElement | undefined;
  if (password) {
    const inputs = Array.from(document.querySelectorAll<HTMLInputElement>("input"));
    const idx = inputs.indexOf(password);
    username =
      inputs.slice(0, idx).reverse().find((i) => ["text", "email"].includes(i.type)) ??
      document.querySelector<HTMLInputElement>('input[autocomplete="username"], input[type="email"]') ??
      undefined;
  }
  return { username, password };
}

// A small fill button injected next to the password field, shown only after a click.
function injectFillAffordance() {
  if (inCrossOriginFrame()) return;
  const { password } = findLoginFields();
  if (!password) return;

  password.addEventListener("focus", async () => {
    const res = await sendBg("search", { query: "", origin: pageOrigin() });
    if (res?.err) return; // locked / no matches → offer nothing
    const items = (res?.payload as { items?: unknown[] })?.items ?? [];
    if (items.length === 0) return;
    showMenu(password, items as Array<{ id: string; title: string; username?: string }>);
  });
}

let menuEl: HTMLDivElement | null = null;
function showMenu(anchor: HTMLElement, items: Array<{ id: string; title: string; username?: string }>) {
  menuEl?.remove();
  const rect = anchor.getBoundingClientRect();
  menuEl = document.createElement("div");
  menuEl.style.cssText = `position:fixed;z-index:2147483647;left:${rect.left}px;top:${rect.bottom + 4}px;background:#0f141c;color:#e6edf3;border:1px solid #28323f;border-radius:10px;padding:6px;font:13px system-ui;min-width:220px;box-shadow:0 8px 24px rgba(0,0,0,.5)`;
  for (const it of items) {
    const row = document.createElement("button");
    row.textContent = `${it.title}${it.username ? " · " + it.username : ""}`;
    row.style.cssText = "display:block;width:100%;text-align:left;background:none;border:0;color:inherit;padding:8px;border-radius:6px;cursor:pointer";
    row.onmouseenter = () => (row.style.background = "#22d3ee22");
    row.onmouseleave = () => (row.style.background = "none");
    row.onclick = () => void fillFrom(it.id);
    menuEl!.appendChild(row);
  }
  document.body.appendChild(menuEl);
  document.addEventListener("click", (e) => {
    if (menuEl && !menuEl.contains(e.target as Node)) menuEl.remove();
  }, { once: true });
}

async function fillFrom(id: string) {
  // Explicit user gesture: request the fields for THIS origin. The desktop re-checks
  // the origin before releasing anything.
  const res = await sendBg("fields", { id, fields: ["username", "password"], origin: pageOrigin(), reason: "autofill" });
  if (res?.err) return;
  const fields = (res?.payload as { fields?: Record<string, string> })?.fields ?? {};
  const { username, password } = findLoginFields();
  if (username && fields.username) setValue(username, fields.username);
  if (password && fields.password) setValue(password, fields.password);
  menuEl?.remove();
}

function setValue(el: HTMLInputElement, value: string) {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter?.call(el, value);
  el.dispatchEvent(new Event("input", { bubbles: true }));
  el.dispatchEvent(new Event("change", { bubbles: true }));
}

// Offer to save on submit.
function watchSubmit() {
  if (inCrossOriginFrame()) return;
  document.addEventListener(
    "submit",
    (e) => {
      const form = e.target as HTMLFormElement;
      const password = form.querySelector<HTMLInputElement>('input[type="password"]');
      if (!password || !password.value) return;
      const username = form.querySelector<HTMLInputElement>('input[type="text"], input[type="email"], input[autocomplete="username"]');
      void sendBg("save_candidate", {
        origin: pageOrigin(),
        username: username?.value ?? "",
        password: password.value,
        title: document.title || location.hostname,
      });
    },
    true,
  );
}

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

if (!inCrossOriginFrame()) {
  injectFillAffordance();
  watchSubmit();
}

export {};
