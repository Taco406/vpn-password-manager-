/**
 * SentinelBridge — the complete contract between the React UI and the native core.
 *
 * Two implementations satisfy this interface:
 *   - the real Tauri bridge (`invoke`/`listen` into sentinel-core), and
 *   - a deterministic in-browser mock seeded from Rust.
 * The UI depends only on this interface, so every screen builds, tests, and
 * screenshots headlessly without a desktop binary or any cloud account.
 */

import type {
  AuditReport,
  ConnectState,
  ConnectionProfile,
  DeviceInfo,
  GeneratedPassword,
  InstanceType,
  ItemDetail,
  ItemSummary,
  ItemType,
  KeyringStatus,
  PassphraseSpec,
  PasswordSpec,
  Region,
  ReportData,
  SessionRow,
  Settings,
  VpnMetrics,
} from "./models";

export type BridgeEvent =
  | { type: "vpn:state"; state: ConnectState }
  | { type: "vpn:metrics"; metrics: VpnMetrics }
  | { type: "clipboard:countdown"; remainingMs: number; field: string }
  | { type: "vault:locked" }
  | { type: "sync:state"; state: "idle" | "syncing" | "error"; detail?: string }
  | { type: "pair:progress"; step: string };

export type Unsubscribe = () => void;

export interface ItemInput {
  id?: string;
  type: ItemType;
  title: string;
  username?: string;
  password?: string;
  urls?: { url: string; mode: "domain" | "host" }[];
  notes?: string;
  tags?: string[];
  totpUri?: string;
  customFields?: { name: string; value: string; secret: boolean }[];
}

export interface AuthState {
  signedIn: boolean;
  email?: string;
  totpEnrolled: boolean;
  /** True when the user has chosen to run without an account (local-only). */
  localOnly: boolean;
}

export interface SentinelBridge {
  // --- session / auth (all optional; the app works local-only) ---
  authStatus(): Promise<AuthState>;
  authStartGoogle(): Promise<{ url: string }>;
  authTotpEnroll(): Promise<{ otpauthUri: string; secret: string }>;
  authTotpVerify(code: string): Promise<void>;
  useLocalOnly(): Promise<void>;
  syncNow(): Promise<{ pushed: boolean; pulled: boolean; version: number }>;
  logout(): Promise<void>;

  // --- keyring / unlock ---
  keyringStatus(): Promise<KeyringStatus>;
  unlockPlatform(): Promise<void>;
  unlockPhoneBegin(): Promise<{ requestId: string }>;
  unlockPhoneAwait(requestId: string): Promise<void>;
  unlockRecovery(key: string): Promise<void>;
  lock(): Promise<void>;
  enrollWrapper(type: "platform" | "phone" | "recovery"): Promise<WrapperEnrollResult>;
  recoveryKitGenerate(): Promise<{ display: string; pdfBase64: string }>;
  recoveryKitVerify(groups: { index: number; value: string }[]): Promise<boolean>;
  /** Dev/mock builds only: simulate a biometric approval. */
  mockBiometricApprove?(): Promise<void>;

  // --- vault ---
  vaultList(): Promise<ItemSummary[]>;
  vaultGet(id: string): Promise<ItemDetail>;
  vaultRevealField(id: string, field: string): Promise<string>;
  vaultCopyField(id: string, field: string): Promise<void>;
  vaultSave(item: ItemInput): Promise<string>;
  /**
   * Mint an ES256 passkey and store it as a new Passkey vault item. The seam Stage B's
   * browser registration flow calls. Returns the new item id, the credential id, and the
   * base64 (std) SEC1 public key — never the private key, which stays sealed in the vault.
   */
  vaultPasskeyCreate(
    rpId: string,
    rpName: string | undefined,
    userName: string,
    userDisplayName: string | undefined,
    userHandleB64u: string,
  ): Promise<{ id: string; credentialId: string; publicKeyB64: string }>;
  vaultDelete(id: string): Promise<void>;
  vaultTotp(id: string): Promise<{ code: string; remainingMs: number }>;
  vaultImport(kind: ImportKind, content: string): Promise<{ imported: number; skipped: number }>;
  vaultExport(kind: "encrypted" | "plain_csv", passphrase?: string): Promise<{ base64: string }>;
  generatorPassword(spec: PasswordSpec): Promise<GeneratedPassword>;
  generatorPassphrase(spec: PassphraseSpec): Promise<GeneratedPassword>;
  healthAudit(): Promise<AuditReport>;
  favicon(domain: string): Promise<{ dataUri?: string }>;

  // --- vpn ---
  vpnRegions(): Promise<Region[]>;
  vpnInstanceTypes(): Promise<InstanceType[]>;
  vpnConnect(regionId: string, instanceType: string, profileId?: string): Promise<void>;
  vpnDisconnect(): Promise<void>;
  vpnState(): Promise<ConnectState>;
  vpnSpeedtest(): Promise<{ downMbps: number; upMbps: number; latencyMs: number }>;
  vpnHistory(range: "week" | "month" | "all"): Promise<SessionRow[]>;
  vpnCostEstimate(): Promise<{ hourlyUsd: number; accruedUsd: number }>;
  vpnProfiles(): Promise<ConnectionProfile[]>;
  vpnProfileSave(profile: ConnectionProfile): Promise<string>;
  reportMonth(year: number, month: number): Promise<ReportData>;

  // --- devices / pairing ---
  pairBegin(): Promise<{ qrPayload: string; verificationCode: string }>;
  pairAwait(): Promise<DeviceInfo>;
  devicesList(): Promise<DeviceInfo[]>;
  deviceRevoke(id: string): Promise<void>;

  // --- settings ---
  settingsGet(): Promise<Settings>;
  settingsSet(settings: Partial<Settings>): Promise<void>;

  // --- events ---
  on(handler: (e: BridgeEvent) => void): Unsubscribe;
}

export interface WrapperEnrollResult {
  type: "platform" | "phone" | "recovery";
  enrolled: boolean;
}

export type ImportKind = "bitwarden_json" | "bitwarden_csv" | "chrome_csv";
