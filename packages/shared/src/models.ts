/**
 * Domain models shared across the desktop UI, the mock bridge, and (by mirroring
 * the Rust `serde` shapes) the real backend. These are the wire types the
 * SentinelBridge speaks.
 */

export type WrapperType = "platform" | "phone" | "recovery";

export interface WrapperInfo {
  type: WrapperType;
  enrolled: boolean;
  label: string;
  /** ISO 8601 */
  createdAt?: string;
}

export interface KeyringStatus {
  locked: boolean;
  wrappers: WrapperInfo[];
  /** True once the recovery kit has been generated AND verified. */
  recoveryVerified: boolean;
}

export type ItemType = "login" | "note" | "card" | "identity";

export interface UrlMatch {
  url: string;
  /** "domain" = registrable-domain match (default); "host" = exact host. */
  mode: "domain" | "host";
}

export interface CustomField {
  name: string;
  value: string;
  secret: boolean;
}

/** Summary shape — NEVER carries secret field values. Safe to list/search. */
export interface ItemSummary {
  id: string;
  type: ItemType;
  title: string;
  username?: string;
  tags: string[];
  faviconDomain?: string;
  hasTotp: boolean;
  updatedAt: string;
  passwordChangedAt?: string;
}

/** Detail shape — secret fields are masked until explicitly revealed. */
export interface ItemDetail extends ItemSummary {
  urls: UrlMatch[];
  notes?: string;
  customFields: CustomField[];
  /** Present only for cards/identities; never contains the raw number in a list. */
  card?: { brand: string; last4?: string; expMonth?: number; expYear?: number };
  identity?: { fullName?: string; email?: string; phone?: string };
}

export interface PasswordSpec {
  length: number;
  lower: boolean;
  upper: boolean;
  digits: boolean;
  symbols: boolean;
  excludeAmbiguous: boolean;
}

export interface PassphraseSpec {
  words: number;
  separator: string;
  capitalize: boolean;
  includeNumber: boolean;
}

export interface GeneratedPassword {
  value: string;
  /** zxcvbn score 0..4 */
  score: number;
  crackDisplay: string;
}

export interface AuditReport {
  reused: { password_group: number; itemIds: string[] }[];
  weak: { itemId: string; score: number }[];
  old: { itemId: string; days: number }[];
  breached: { itemId: string; count: number }[];
  score: number; // 0..100 overall health
}

// --- VPN ------------------------------------------------------------------

export type ConnectStage =
  | "idle"
  | "creatingInstance"
  | "booting"
  | "exchangingKeys"
  | "startingTunnel"
  | "connected"
  | "disconnecting"
  | "destroying"
  | "failed";

export interface ConnectState {
  stage: ConnectStage;
  region?: string;
  instanceType?: string;
  /** ISO 8601, present when connected */
  since?: string;
  egressIp?: string;
  detail?: string;
}

export interface Region {
  id: string;
  label: string;
  country: string;
  lat: number;
  lon: number;
  latencyMs?: number;
  medianDownMbps?: number;
}

export interface InstanceType {
  id: string;
  label: string;
  vcpus: number;
  memoryMb: number;
  hourlyUsd: number;
}

export interface VpnMetrics {
  /** bytes/sec */
  rx: number;
  tx: number;
  cpuPct: number;
  memPct: number;
  nicPct: number;
  latencyMs: number;
  ts: number;
}

export interface SessionRow {
  id: string;
  region: string;
  instanceType: string;
  startedAt: string;
  endedAt?: string;
  bytesRx: number;
  bytesTx: number;
  costUsd: number;
  peakCpuPct?: number;
  downMbps?: number;
  upMbps?: number;
}

export interface ConnectionProfile {
  id: string;
  name: string;
  regionId: string;
  instanceType: string;
  killSwitch: boolean;
  splitTunnelApps: string[];
  ssidTriggers: string[];
}

export interface ReportData {
  year: number;
  month: number;
  sessions: number;
  hours: number;
  bytesTotal: number;
  costUsd: number;
  commercialVpnUsd: number;
  byRegion: { region: string; hours: number; bytes: number }[];
  bestDownMbps: number;
  worstDownMbps: number;
}

export interface DeviceInfo {
  id: string;
  name: string;
  platform: "windows" | "macos" | "linux" | "ios";
  status: "pending" | "approved" | "revoked";
  createdAt: string;
  current: boolean;
}

export interface Settings {
  theme: "dark" | "light" | "system";
  reducedMotion: boolean;
  autoLockMinutes: number;
  clipboardClearSeconds: number;
  killSwitchDefault: boolean;
  defaultRegion?: string;
  ssidAllowlist: string[];
  /** VPN routing mode. Default "full" routes all traffic through the tunnel; "split" routes
   *  only the destinations in `splitRoutes`. */
  tunnelMode?: "full" | "split";
  /** In "split" mode, the CIDRs that route through the VPN (everything else stays off-VPN). */
  splitRoutes?: string[];
  /** Set once the user has seen (or skipped) the first-run setup wizard. Absent = first run. */
  onboardingComplete?: boolean;
  telemetry: false; // there is nothing to send; always off.
}
