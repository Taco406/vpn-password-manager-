# The built-in terminal (v0.1.64)

NorthKey can now open a full root command line on your servers, inside the app —
no separate terminal, no setting up SSH keys by hand. This is the most powerful
thing the app does (it runs commands as **root** on your server), so it's wrapped
in several safety checks. This doc is both the how-to and the honest test script.

## What it is

Server side panel → **Access** tab → **Connect**. You get a real interactive
shell: arrow keys, text editors, `htop`, tab-completion — everything a normal SSH
session does. Use it to restart a service, open a firewall port, read a log, or
poke around.

## How the safety works (plain-English)

- **NorthKey's own key.** The first time, NorthKey makes its own SSH key and
  shows you one line to paste onto the server. After that it signs in on its own.
  The private key lives only in this computer's keychain — it is **never** sent to
  your phone or the sync server.
- **Server-identity check (this is the important one).** On the first connect,
  NorthKey records the server's identity fingerprint and shows it to you. Every
  later connect checks it. If the fingerprint changes, NorthKey **refuses** and
  warns you — that's how it catches someone trying to sit in the middle and
  impersonate your server. The old "open a terminal" button never checked this.
- **It only opens when you allow it.** Your vault must be unlocked, and if this
  computer has a fingerprint reader / Windows Hello, NorthKey asks for it right
  before opening the shell.
- **Locking closes it.** Lock your vault and every open terminal closes at once.
- **A local record.** Each session (which server, when) is written to a history
  that stays on this computer and never syncs.

---

## Test script (~10 minutes, Windows or Mac)

Do these in order. Copy one line at a time.

### 1 — Get on 0.1.64

1. Open NorthKey. If it offers **0.1.64**, accept it and relaunch. Otherwise
   download `NorthKey_0.1.64_x64-setup.exe` (Windows) or the `.dmg` (Mac) from the
   newest GitHub release and run it over the top.
2. Settings → the version badge should read **0.1.64**.

### 2 — Set up the key (one time per server)

1. Go to **Servers**, click a server (say **coolify**), and open the **Access**
   tab in the side panel.
2. Expand **Set up access**. Click **Copy command**.
3. Click **SSH to …** under "Open a separate terminal" (or use your own terminal),
   and paste the command. Press Enter. It should return with no error.
4. Back in NorthKey, tick **I've installed it**.

### 3 — Connect

1. Click **Connect**. If your computer has a fingerprint reader / Windows Hello,
   confirm the prompt.
2. First time only: a highlighted box shows the server's fingerprint
   (`SHA256:…`). This is expected — it's NorthKey pinning the key.
3. You should land at a `root@…:~#` prompt. Type:

   ```
   whoami
   ```

   It should print `root`.
4. Try something interactive to prove it's a real shell:

   ```
   htop
   ```

   Arrow keys should work; press `q` to quit. (If `htop` isn't installed, `top`
   works — press `q` to quit.)

### 4 — The safety checks

1. With the terminal open, **lock your vault** (Lock button, bottom-left). The
   terminal should immediately show `[session closed]`. Unlock again.
2. Open **Access → Advanced**. You should see the session(s) you just ran listed
   under the history. This is local-only.

### 5 — If something's wrong

- **"The server rejected NorthKey's key."** The one-time setup (step 2) didn't
  land. Redo it — make sure you pasted the whole command.
- **"HOST KEY CHANGED."** If you did **not** rebuild this server, stop and don't
  proceed — something is off. If you **did** rebuild it, open **Access →
  Advanced → Reset pinned key**, then Connect again.
- **Connect does nothing / times out.** Port 22 may be closed. Use **Access →
  "Can I reach a port?" → SSH (22)** to check — "timed out" means a firewall is
  blocking it.

Report back which step you reached and exactly what you saw.
