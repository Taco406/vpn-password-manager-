// Popup logic: shows the VPN pill, a vault search, and copy actions — all proxied to
// the desktop through the background worker. When the desktop is locked it shows a
// locked state and holds zero credential data.

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const runtime = (globalThis as any).chrome?.runtime;

interface SearchItem {
  id: string;
  title: string;
  username?: string;
  faviconDomain?: string;
}

function bg(cmd: string, payload?: unknown): Promise<{ ok?: boolean; payload?: unknown; err?: { code: string } } | undefined> {
  return new Promise((resolve) => {
    try {
      runtime.sendMessage({ cmd, payload }, (r: unknown) => resolve(r as never));
    } catch {
      resolve(undefined);
    }
  });
}

async function currentOrigin(): Promise<string> {
  try {
    const [tab] = await runtime.sendMessage ? [{ url: "" }] : [{ url: "" }];
    return tab?.url ? new URL(tab.url).origin : "";
  } catch {
    return "";
  }
}

function fav(title: string): string {
  const hue = [...title].reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
  return `background:hsl(${hue} 40% 22%);color:hsl(${hue} 80% 72%)`;
}

async function render(query = "") {
  const app = document.getElementById("app")!;
  const status = (await bg("status")) as unknown as { locked: boolean; vpn: { stage: string; region?: string } } | undefined;

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

  if (!status || status.locked) {
    app.innerHTML = `<div class="locked"><b>SENTINEL is locked</b>Open the app and unlock to search your vault. Nothing is available here while locked.</div>`;
    return;
  }

  const origin = await currentOrigin();
  const res = await bg("search", { query, origin });
  const items = ((res?.payload as { items?: SearchItem[] })?.items ?? []) as SearchItem[];

  app.innerHTML = `
    <div class="search"><span>🔎</span><input id="q" placeholder="Search vault" value="${query}"/></div>
    <ul>${items
      .map(
        (it) => `<li data-id="${it.id}">
          <span class="fav" style="${fav(it.title)}">${it.title.charAt(0).toUpperCase()}</span>
          <span><span class="title">${it.title}</span><br/><span class="user">${it.username ?? ""}</span></span>
          <span class="actions">
            <button data-act="user">User</button>
            <button data-act="pass">Pass</button>
          </span>
        </li>`,
      )
      .join("")}</ul>`;

  const q = document.getElementById("q") as HTMLInputElement | null;
  q?.addEventListener("input", () => render(q.value));
  app.querySelectorAll<HTMLButtonElement>("button[data-act]").forEach((btn) => {
    btn.addEventListener("click", async (e) => {
      e.stopPropagation();
      const li = btn.closest("li")!;
      const id = li.getAttribute("data-id")!;
      const field = btn.dataset.act === "user" ? "username" : "password";
      const r = await bg("fields", { id, fields: [field], origin, reason: "copy" });
      const val = (r?.payload as { fields?: Record<string, string> })?.fields?.[field];
      if (val) await navigator.clipboard.writeText(val);
      btn.textContent = "✓";
      setTimeout(() => (btn.textContent = field === "username" ? "User" : "Pass"), 900);
    });
  });
}

void render();
