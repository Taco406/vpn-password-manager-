// Popup: VPN pill + vault search for the current site, with fill / copy / generate — all
// proxied to the desktop through the background worker. Holds zero credential data; when the
// desktop is locked it shows a locked state. Vault-supplied strings are inserted via
// textContent (never innerHTML) so a crafted title can't inject markup.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const runtime = (globalThis as any).chrome?.runtime;
// eslint-disable-next-line @typescript-eslint/no-explicit-any
const tabs = (globalThis as any).chrome?.tabs;

interface SearchItem {
  id: string;
  title: string;
  username?: string;
  faviconDomain?: string;
}

function bg(
  cmd: string,
  payload?: unknown,
): Promise<{ ok?: boolean; payload?: unknown; err?: { code: string } } | undefined> {
  return new Promise((resolve) => {
    try {
      runtime.sendMessage({ cmd, payload }, (r: unknown) => resolve(r as never));
    } catch {
      resolve(undefined);
    }
  });
}

async function activeTab(): Promise<{ id?: number; origin: string; host: string }> {
  try {
    const [tab] = await tabs.query({ active: true, currentWindow: true });
    if (tab?.url) {
      const u = new URL(tab.url);
      return { id: tab.id, origin: u.origin, host: u.host };
    }
    return { id: tab?.id, origin: "", host: "" };
  } catch {
    return { origin: "", host: "" };
  }
}

function favStyle(title: string): string {
  const hue = [...title].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
  return `background:hsl(${hue} 40% 22%);color:hsl(${hue} 80% 74%)`;
}

let toastTimer: ReturnType<typeof setTimeout> | undefined;
function toast(msg: string) {
  const t = document.getElementById("toast")!;
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove("show"), 1400);
}

function node<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  cls?: string,
  text?: string,
): HTMLElementTagNameMap[K] {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
}

async function copyField(id: string, field: "username" | "password", origin: string, btn: HTMLButtonElement) {
  const r = await bg("fields", { id, fields: [field], origin, reason: "copy" });
  const val = (r?.payload as { fields?: Record<string, string> })?.fields?.[field];
  if (!val) {
    toast("Nothing to copy");
    return;
  }
  await navigator.clipboard.writeText(val);
  const prev = btn.textContent;
  btn.textContent = "✓";
  toast(field === "username" ? "Username copied" : "Password copied");
  setTimeout(() => (btn.textContent = prev), 900);
}

async function render(query = "") {
  const app = document.getElementById("app")!;
  const status = (await bg("status")) as unknown as
    | { locked: boolean; vpn: { stage: string; region?: string } }
    | undefined;

  // VPN pill.
  const dot = document.getElementById("vpnDot")!;
  const label = document.getElementById("vpnLabel")!;
  if (status?.vpn?.stage === "connected") {
    dot.classList.add("on");
    label.textContent = status.vpn.region ? `via ${status.vpn.region}` : "connected";
  } else {
    dot.classList.remove("on");
    label.textContent = "VPN off";
  }

  const tab = await activeTab();
  document.getElementById("site")!.textContent = tab.host || "";

  if (!status || status.locked) {
    app.replaceChildren();
    const box = node("div", "locked");
    box.appendChild(node("b", undefined, "NorthKey is locked"));
    box.appendChild(
      node("span", undefined, "Open the desktop app and unlock to search your vault."),
    );
    app.appendChild(box);
    return;
  }

  const res = await bg("search", { query, origin: tab.origin });
  const items = ((res?.payload as { items?: SearchItem[] })?.items ?? []) as SearchItem[];

  app.replaceChildren();

  const search = node("div", "search");
  search.appendChild(node("span", undefined, "🔎"));
  const input = node("input");
  input.placeholder = "Search vault";
  input.value = query;
  input.addEventListener("input", () => render(input.value));
  search.appendChild(input);
  app.appendChild(search);

  if (items.length === 0) {
    app.appendChild(
      node(
        "div",
        "empty",
        query ? "No matches." : `No saved logins for ${tab.host || "this site"} yet.`,
      ),
    );
    setTimeout(() => input.focus(), 0);
    return;
  }

  const ul = node("ul");
  for (const it of items) {
    const li = node("li");
    const fav = node("span", "fav", (it.title || "?").charAt(0).toUpperCase());
    fav.setAttribute("style", favStyle(it.title || "?"));
    li.appendChild(fav);

    const meta = node("div", "meta");
    meta.appendChild(node("div", "title", it.title));
    meta.appendChild(node("div", "user", it.username ?? ""));
    li.appendChild(meta);

    const actions = node("div", "actions");
    if (tab.id !== undefined) {
      const fill = node("button", "fill", "Fill");
      fill.addEventListener("click", async () => {
        try {
          await tabs.sendMessage(tab.id, { cmd: "fill", id: it.id });
          window.close();
        } catch {
          toast("Open a login page first");
        }
      });
      actions.appendChild(fill);
    }
    const user = node("button", undefined, "User");
    user.addEventListener("click", () => void copyField(it.id, "username", tab.origin, user));
    const pass = node("button", undefined, "Pass");
    pass.addEventListener("click", () => void copyField(it.id, "password", tab.origin, pass));
    actions.appendChild(user);
    actions.appendChild(pass);
    li.appendChild(actions);
    ul.appendChild(li);
  }
  app.appendChild(ul);
  setTimeout(() => input.focus(), 0);
}

document.getElementById("genBtn")?.addEventListener("click", async () => {
  const r = await bg("generate", {});
  const pw = (r?.payload as { password?: string })?.password;
  if (!pw) {
    toast("Couldn't generate");
    return;
  }
  await navigator.clipboard.writeText(pw);
  toast("Strong password copied");
});

void render();
