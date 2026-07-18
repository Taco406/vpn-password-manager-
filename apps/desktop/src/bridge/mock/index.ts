// The deterministic in-browser mock implementing SentinelBridge. Seeded from Rust
// (seed.json). Supports a `?freeze=1&t=SECONDS` query to pin all time-based state for
// pixel-stable screenshots.

import type {
  AuditReport,
  AuthState,
  BridgeEvent,
  ConnectState,
  ConnectionProfile,
  DeviceInfo,
  GeneratedPassword,
  ImportKind,
  InstanceType,
  ItemDetail,
  ItemInput,
  ItemSummary,
  KeyringStatus,
  PassphraseSpec,
  PasswordSpec,
  Region,
  ReportData,
  SentinelBridge,
  SessionRow,
  Settings,
  Unsubscribe,
  WrapperEnrollResult,
} from "@sentinel/shared";
import { seed, type SeedItem } from "./seed";
import { CONNECT_TIMELINE, sampleAt } from "./vpnSim";

const params = new URLSearchParams(typeof location !== "undefined" ? location.search : "");
const FROZEN = params.get("freeze") === "1";
const FROZEN_T = Number(params.get("t") ?? "42");

const WEAK = new Set(["password", "12345678", "qwerty", "hunter2", "hunter2-reused"]);
const BREACHED: Record<string, number> = {
  "hunter2-reused": 4210,
  password: 9_659_365,
  "12345678": 2_938_594,
};
const OLD_DAYS = 180;

function nowMs(): number {
  return FROZEN ? FROZEN_T * 1000 : Date.now();
}

type Listener = (e: BridgeEvent) => void;

class MockBridge implements SentinelBridge {
  private items: SeedItem[] = seed.items.map((i) => ({ ...i }));
  private listeners = new Set<Listener>();
  private connect: ConnectState = { stage: "idle" };
  private connectStartMs = 0;
  private connectTimers: number[] = [];
  private metricsTimer: number | null = null;
  private auth: AuthState = { signedIn: false, totpEnrolled: false, localOnly: true };
  private locked = true;
  private recoveryVerified = false;
  private wrappers = {
    platform: true,
    phone: false,
    recovery: true,
  };
  private settings: Settings = {
    theme: "dark",
    reducedMotion: false,
    autoLockMinutes: 10,
    clipboardClearSeconds: 30,
    killSwitchDefault: true,
    defaultRegion: "us-east",
    ssidAllowlist: ["home", "office"],
    telemetry: false,
  };
  private devices: DeviceInfo[] = [
    { id: "dev-desktop", name: "This Mac", platform: "macos", status: "approved", createdAt: iso(-30), current: true },
    { id: "dev-iphone", name: "iPhone 16 Pro", platform: "ios", status: "approved", createdAt: iso(-12), current: false },
  ];

  private emit(e: BridgeEvent) {
    for (const l of this.listeners) l(e);
  }

  on(handler: Listener): Unsubscribe {
    this.listeners.add(handler);
    return () => this.listeners.delete(handler);
  }

  // --- auth ---
  async authStatus() {
    return this.auth;
  }
  async authStartGoogle() {
    return { url: "https://accounts.google.com/o/oauth2/v2/auth?client_id=sentinel..." };
  }
  async authTotpEnroll() {
    return {
      otpauthUri: "otpauth://totp/SENTINEL:jackson?secret=JBSWY3DPEHPK3PXP&issuer=SENTINEL",
      secret: "JBSW Y3DP EHPK 3PXP",
    };
  }
  async authTotpVerify(_code: string) {
    this.auth = { signedIn: true, email: "jackson@example.com", totpEnrolled: true, localOnly: false };
  }
  async useLocalOnly() {
    this.auth = { signedIn: false, totpEnrolled: false, localOnly: true };
  }
  async syncNow() {
    this.emit({ type: "sync:state", state: "syncing" });
    this.emit({ type: "sync:state", state: "idle" });
    return { pushed: true, pulled: false, version: 7 };
  }
  async logout() {
    this.auth = { signedIn: false, totpEnrolled: false, localOnly: true };
  }

  // --- keyring / unlock ---
  async keyringStatus(): Promise<KeyringStatus> {
    return {
      locked: this.locked,
      recoveryVerified: this.recoveryVerified,
      wrappers: [
        { type: "platform", enrolled: this.wrappers.platform, label: "Touch ID", createdAt: iso(-30) },
        { type: "phone", enrolled: this.wrappers.phone, label: "iPhone 16 Pro" },
        { type: "recovery", enrolled: this.wrappers.recovery, label: "Recovery Kit", createdAt: iso(-30) },
      ],
    };
  }
  async unlockPlatform() {
    this.locked = false;
  }
  async unlockPhoneBegin() {
    return { requestId: "req-" + Math.floor(nowMs()) };
  }
  async unlockPhoneAwait(_requestId: string) {
    await delay(FROZEN ? 0 : 1600);
    this.locked = false;
  }
  async unlockRecovery(_key: string) {
    this.locked = false;
  }
  async lock() {
    this.locked = true;
    this.emit({ type: "vault:locked" });
  }
  async enrollWrapper(type: "platform" | "phone" | "recovery"): Promise<WrapperEnrollResult> {
    this.wrappers[type] = true;
    return { type, enrolled: true };
  }
  async recoveryKitGenerate() {
    return {
      display: "SNTL-A6GRV-EXGN8-30WJC-79VXR-WBBQP-S88WR",
      pdfBase64: "",
    };
  }
  async recoveryKitVerify(_groups: { index: number; value: string }[]) {
    this.recoveryVerified = true;
    return true;
  }
  async mockBiometricApprove() {
    /* no-op: the mock platform wrapper is always approvable */
  }

  // --- vault ---
  private toSummary(i: SeedItem): ItemSummary {
    return {
      id: i.id,
      type: i.type,
      title: i.title,
      username: i.username ?? undefined,
      tags: i.tags,
      faviconDomain: i.faviconDomain ?? undefined,
      hasTotp: i.hasTotp,
      updatedAt: i.updatedAt,
      passwordChangedAt: i.passwordChangedAt ?? undefined,
    };
  }
  async vaultList() {
    return this.items.map((i) => this.toSummary(i));
  }
  async vaultGet(id: string): Promise<ItemDetail> {
    const i = this.items.find((x) => x.id === id);
    if (!i) throw new Error("not found");
    return {
      ...this.toSummary(i),
      urls: i.urls.map((url) => ({ url, mode: "domain" as const })),
      notes: i.notes ?? undefined,
      customFields: [],
    };
  }
  async vaultRevealField(id: string, field: string) {
    const i = this.items.find((x) => x.id === id);
    if (!i) throw new Error("not found");
    if (field === "password") return i.password ?? "";
    if (field === "username") return i.username ?? "";
    return "";
  }
  async vaultCopyField(_id: string, field: string) {
    // Start a 30s auto-clear countdown with visible ticks.
    let remaining = this.settings.clipboardClearSeconds * 1000;
    this.emit({ type: "clipboard:countdown", remainingMs: remaining, field });
    if (FROZEN) return;
    const step = 1000;
    const timer = window.setInterval(() => {
      remaining -= step;
      this.emit({ type: "clipboard:countdown", remainingMs: Math.max(0, remaining), field });
      if (remaining <= 0) window.clearInterval(timer);
    }, step);
  }
  async vaultSave(item: ItemInput) {
    const id = item.id ?? "new-" + Math.floor(nowMs());
    const existing = this.items.find((x) => x.id === id);
    const rec: SeedItem = {
      id,
      type: item.type,
      title: item.title,
      username: item.username ?? null,
      password: item.password ?? null,
      tags: item.tags ?? [],
      faviconDomain: item.urls?.[0]?.url ? hostOf(item.urls[0].url) : null,
      hasTotp: !!item.totpUri,
      totpUri: item.totpUri ?? null,
      urls: (item.urls ?? []).map((u) => u.url),
      notes: item.notes ?? null,
      updatedAt: new Date(nowMs()).toISOString(),
      passwordChangedAt: new Date(nowMs()).toISOString(),
    };
    if (existing) Object.assign(existing, rec);
    else this.items.unshift(rec);
    return id;
  }
  async vaultDelete(id: string) {
    this.items = this.items.filter((x) => x.id !== id);
  }
  async vaultTotp(_id: string) {
    // A stable, plausible code when frozen.
    const t = Math.floor(nowMs() / 1000);
    const code = (((t / 30) | 0) % 1_000_000).toString().padStart(6, "0");
    return { code, remainingMs: 30000 - (nowMs() % 30000) };
  }
  async vaultImport(_kind: ImportKind, _content: string) {
    return { imported: 25, skipped: 0 };
  }
  async vaultExport(_kind: "encrypted" | "plain_csv", _passphrase?: string) {
    return { base64: "U0VYUAE..." };
  }
  async generatorPassword(spec: PasswordSpec): Promise<GeneratedPassword> {
    const value = genCharset(spec);
    return { value, score: strengthScore(value), crackDisplay: "centuries" };
  }
  async generatorPassphrase(spec: PassphraseSpec): Promise<GeneratedPassword> {
    const words = ["falcon", "cedar", "harbor", "quartz", "meadow", "cipher", "lantern", "zephyr"];
    const parts = Array.from({ length: spec.words }, (_, i) =>
      spec.capitalize ? cap(words[(i * 3 + 1) % words.length]) : words[(i * 3 + 1) % words.length],
    );
    let value = parts.join(spec.separator);
    if (spec.includeNumber) value += spec.separator + "42";
    return { value, score: 4, crackDisplay: "centuries" };
  }
  async healthAudit(): Promise<AuditReport> {
    return computeAudit(this.items);
  }
  async favicon(_domain: string) {
    return {};
  }

  // --- vpn ---
  async vpnRegions(): Promise<Region[]> {
    return seed.regions.map((r) => ({
      id: r.id,
      label: r.label,
      country: r.country,
      lat: r.lat,
      lon: r.lon,
      latencyMs: r.latencyMs,
      medianDownMbps: r.medianDownMbps,
    }));
  }
  async vpnInstanceTypes(): Promise<InstanceType[]> {
    return seed.instanceTypes.map((t) => ({
      id: t.id,
      label: t.label,
      vcpus: t.vcpus,
      memoryMb: t.memoryMb,
      hourlyUsd: t.hourlyUsd,
    }));
  }
  async vpnConnect(regionId: string, instanceType: string, _profileId?: string) {
    this.clearConnectTimers();
    const region = seed.regions.find((r) => r.id === regionId);
    this.connectStartMs = nowMs();
    for (const step of CONNECT_TIMELINE) {
      const fire = () => {
        this.connect = {
          stage: step.stage as ConnectState["stage"],
          region: regionId,
          instanceType,
          detail: narrate(step.stage, region?.label ?? regionId),
          ...(step.stage === "connected"
            ? { since: new Date(nowMs()).toISOString(), egressIp: "203.0.113.42" }
            : {}),
        };
        this.emit({ type: "vpn:state", state: this.connect });
        if (step.stage === "connected") this.startMetrics();
      };
      if (FROZEN) fire();
      else this.connectTimers.push(window.setTimeout(fire, step.atMs));
    }
  }
  async vpnDisconnect() {
    this.clearConnectTimers();
    this.stopMetrics();
    this.connect = { stage: "idle" };
    this.emit({ type: "vpn:state", state: this.connect });
  }
  async vpnState() {
    return this.connect;
  }
  async vpnSpeedtest() {
    return { downMbps: 912, upMbps: 361, latencyMs: 18 };
  }
  async vpnHistory(_range: "week" | "month" | "all"): Promise<SessionRow[]> {
    return seed.history.map((s) => ({
      id: s.id,
      region: s.region,
      instanceType: s.instanceType,
      startedAt: s.startedAt,
      endedAt: s.endedAt,
      bytesRx: s.bytesRx,
      bytesTx: s.bytesTx,
      costUsd: s.costUsd,
      peakCpuPct: s.peakCpuPct,
      downMbps: s.downMbps,
      upMbps: s.upMbps,
    }));
  }
  async vpnCostEstimate() {
    const elapsed = Math.max(0, (nowMs() - this.connectStartMs) / 1000);
    return { hourlyUsd: 0.0075, accruedUsd: (0.0075 * elapsed) / 3600 };
  }
  async vpnProfiles(): Promise<ConnectionProfile[]> {
    return seed.profiles.map((p) => ({
      id: p.id,
      name: p.name,
      regionId: p.regionId,
      instanceType: p.instanceType,
      killSwitch: p.killSwitch,
      splitTunnelApps: p.splitTunnelApps,
      ssidTriggers: p.ssidTriggers,
    }));
  }
  async vpnProfileSave(profile: ConnectionProfile) {
    return profile.id;
  }
  async reportMonth(year: number, month: number): Promise<ReportData> {
    return computeReport(seed.history, year, month);
  }

  // --- devices / pairing ---
  async pairBegin() {
    return {
      qrPayload: JSON.stringify({ v: 1, pairingId: "pair-abc", relay: "sentinel.local" }),
      verificationCode: "418 302",
    };
  }
  async pairAwait(): Promise<DeviceInfo> {
    await delay(FROZEN ? 0 : 1500);
    const d: DeviceInfo = { id: "dev-new", name: "iPhone 16 Pro", platform: "ios", status: "approved", createdAt: iso(0), current: false };
    return d;
  }
  async devicesList() {
    return this.devices;
  }
  async deviceRevoke(id: string) {
    this.devices = this.devices.map((d) => (d.id === id ? { ...d, status: "revoked" as const } : d));
  }

  // --- settings ---
  async settingsGet() {
    return this.settings;
  }
  async settingsSet(patch: Partial<Settings>) {
    this.settings = { ...this.settings, ...patch };
  }

  // --- internals ---
  private startMetrics() {
    this.stopMetrics();
    const emitSample = (t: number) => {
      const s = sampleAt(t);
      this.emit({
        type: "vpn:metrics",
        metrics: { rx: s.rx, tx: s.tx, cpuPct: s.cpuPct, memPct: s.memPct, nicPct: s.nicPct, latencyMs: s.latencyMs, ts: nowMs() },
      });
    };
    if (FROZEN) {
      // Emit a full window of samples so the throughput chart reads as a live sweep in
      // pixel-stable screenshots, ending at the frozen time.
      for (let i = 89; i >= 0; i--) emitSample(Math.max(0, FROZEN_T - i * 2));
      return;
    }
    emitSample((nowMs() - this.connectStartMs) / 1000);
    this.metricsTimer = window.setInterval(() => emitSample((nowMs() - this.connectStartMs) / 1000), 2000);
  }
  private stopMetrics() {
    if (this.metricsTimer !== null) window.clearInterval(this.metricsTimer);
    this.metricsTimer = null;
  }
  private clearConnectTimers() {
    this.connectTimers.forEach((t) => window.clearTimeout(t));
    this.connectTimers = [];
  }
}

function narrate(stage: string, region: string): string {
  switch (stage) {
    case "creatingInstance":
      return `Provisioning server in ${region}…`;
    case "booting":
      return `Booting exit node…`;
    case "exchangingKeys":
      return `Handshaking…`;
    case "startingTunnel":
      return `Bringing the tunnel up…`;
    case "connected":
      return `Secured — you are browsing from ${region}`;
    default:
      return "";
  }
}

function computeAudit(items: SeedItem[]): AuditReport {
  const byPw = new Map<string, string[]>();
  for (const i of items) if (i.password) byPw.set(i.password, [...(byPw.get(i.password) ?? []), i.id]);
  const reused = [...byPw.entries()]
    .filter(([, ids]) => ids.length > 1)
    .map(([, ids], n) => ({ password_group: n, itemIds: ids }));
  const weak: { itemId: string; score: number }[] = [];
  const old: { itemId: string; days: number }[] = [];
  const breached: { itemId: string; count: number }[] = [];
  const now = Date.parse("2026-06-05T12:00:00Z");
  for (const i of items) {
    if (!i.password) continue;
    if (WEAK.has(i.password)) weak.push({ itemId: i.id, score: 0 });
    if (i.passwordChangedAt) {
      const days = (now - Date.parse(i.passwordChangedAt)) / 86_400_000;
      if (days > OLD_DAYS) old.push({ itemId: i.id, days: Math.round(days) });
    }
    if (BREACHED[i.password]) breached.push({ itemId: i.id, count: BREACHED[i.password] });
  }
  const reusedCount = reused.reduce((a, g) => a + g.itemIds.length, 0);
  const score = Math.max(0, 100 - reusedCount * 8 - weak.length * 6 - breached.length * 12 - old.length * 3);
  return { reused, weak, old, breached, score };
}

function computeReport(history: import("./seed").SeedSession[], year: number, month: number): ReportData {
  const totalBytes = history.reduce((a, s) => a + s.bytesRx + s.bytesTx, 0);
  const hours = history.reduce((a, s) => a + (Date.parse(s.endedAt) - Date.parse(s.startedAt)) / 3_600_000, 0);
  const cost = history.reduce((a, s) => a + s.costUsd, 0);
  const byRegionMap = new Map<string, { hours: number; bytes: number }>();
  for (const s of history) {
    const e = byRegionMap.get(s.region) ?? { hours: 0, bytes: 0 };
    e.hours += (Date.parse(s.endedAt) - Date.parse(s.startedAt)) / 3_600_000;
    e.bytes += s.bytesRx + s.bytesTx;
    byRegionMap.set(s.region, e);
  }
  return {
    year,
    month,
    sessions: history.length,
    hours: Math.round(hours * 10) / 10,
    bytesTotal: totalBytes,
    costUsd: Math.round(cost * 100) / 100,
    commercialVpnUsd: 12.99,
    byRegion: [...byRegionMap.entries()].map(([region, v]) => ({ region, hours: Math.round(v.hours * 10) / 10, bytes: v.bytes })),
    bestDownMbps: Math.max(...history.map((s) => s.downMbps)),
    worstDownMbps: Math.min(...history.map((s) => s.downMbps)),
  };
}

function genCharset(spec: PasswordSpec): string {
  let alpha = "";
  if (spec.lower) alpha += "abcdefghijkmnpqrstuvwxyz";
  if (spec.upper) alpha += "ABCDEFGHJKLMNPQRSTUVWXYZ";
  if (spec.digits) alpha += "23456789";
  if (spec.symbols) alpha += "!@#$%^&*()-_=+";
  if (!alpha) alpha = "abcdef";
  let out = "";
  const rnd = new Uint32Array(spec.length);
  crypto.getRandomValues(rnd);
  for (let i = 0; i < spec.length; i++) out += alpha[rnd[i] % alpha.length];
  return out;
}

function strengthScore(pw: string): number {
  let s = 0;
  if (pw.length >= 12) s++;
  if (/[A-Z]/.test(pw) && /[a-z]/.test(pw)) s++;
  if (/[0-9]/.test(pw)) s++;
  if (/[^A-Za-z0-9]/.test(pw)) s++;
  return Math.min(4, s);
}

function cap(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return url;
  }
}
function iso(daysFromNow: number): string {
  return new Date(nowMs() + daysFromNow * 86_400_000).toISOString();
}
function delay(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

export const mockBridge = new MockBridge();
export { FROZEN, FROZEN_T };
