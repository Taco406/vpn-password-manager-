# Testing the real VPN end-to-end (autonomous)

The real VPN can only be exercised on a real **Windows** machine with **WireGuard** installed and
**Administrator** rights, against a **live Linode** — none of which the normal CI runners have. This
sets up an on-demand GitHub workflow that runs the app's built-in self-test on a machine you control,
so a real connect can be verified without you being the guinea pig.

## What it does

`.github/workflows/vpn-live-test.yml` builds `sentinel-desktop` and runs its built-in
**`--vpn-selftest`** mode (see `apps/desktop/src-tauri/src/vpn.rs`), which:

1. spins up a throwaway Linode exit node,
2. brings up a WireGuard tunnel with **minimal routing** (only the `10.66.0.0/24` tunnel subnet — it
   never touches the machine's default route or DNS, so it can't disrupt the runner's connectivity),
3. verifies a **real WireGuard handshake**, then
4. **destroys the node** and exits `0` (pass) or `1` (fail), printing a staged report.

## One-time setup

You need two things:

### 1. A self-hosted Windows runner

Hosted GitHub Windows runners can't install the WireGuard tun driver, so the runner must be a machine
you control (a spare PC, or a small cloud Windows VM — e.g. an Azure/EC2 Windows instance):

1. Install **WireGuard for Windows** ([wireguard.com/install](https://www.wireguard.com/install/)).
2. Repo → **Settings → Actions → Runners → New self-hosted runner**, pick **Windows**, and follow the
   steps to register it. Give it the default labels (`self-hosted`, `windows` are what the workflow
   targets).
3. Run the runner **as Administrator** — creating a WireGuard tunnel is a privileged operation. If you
   install it as a service, set that service to run under an admin account; otherwise launch
   `run.cmd` from an elevated terminal.

### 2. A Linode token secret

Repo → **Settings → Secrets and variables → Actions → New repository secret**:

- **Name:** `SENTINEL_LINODE_TOKEN`
- **Value:** a Linode Personal Access Token with **Read/Write** on **Linodes**.

Each run costs a few cents of Linode time; the node is always destroyed at the end (and the app's
orphan-sweep would reap it anyway).

## Running it

Repo → **Actions → "VPN live test" → Run workflow**, optionally pick a region (default `us-east`), and
run. The job logs show each stage and a final **PASS/FAIL**; a failure reports the tunnel's tx/rx byte
counters so you can tell a client-side problem (tx=0) from a server-side one (tx>0, rx=0).

This is the same self-test you can run by hand from an Administrator terminal:

```
SENTINEL.exe --vpn-selftest us-east
```
