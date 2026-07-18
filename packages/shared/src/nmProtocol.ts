/**
 * Native-messaging protocol shared by the Chrome extension, the native-messaging
 * host, and (mirrored in Rust `nm::protocol`) the desktop core. Wire framing on both
 * hops is a u32 little-endian length prefix followed by UTF-8 JSON of `NmEnvelope`.
 *
 * Trust boundary: the desktop validates the requesting page origin against each
 * item's saved URL match BEFORE releasing any field. The extension never receives
 * the vault key and, while the desktop is locked, receives no credential data at all.
 */

export interface NmEnvelope {
  id: string;
  type: NmType;
  ok?: boolean;
  payload?: unknown;
  err?: { code: NmErrorCode; message: string };
}

export type NmType =
  | "hello"
  | "status.subscribe"
  | "status.event"
  | "vault.search"
  | "vault.fields.get"
  | "vault.totp.get"
  | "vault.generate"
  | "vault.save_candidate"
  | "lock.event";

export type NmErrorCode = "LOCKED" | "BAD_ORIGIN" | "NOT_FOUND" | "BAD_REQUEST" | "INTERNAL";

export interface HelloPayload {
  caps: string[];
  appVersion: string;
  locked: boolean;
}

export interface VaultSearchRequest {
  query: string;
  origin: string;
}

export interface VaultSearchResultItem {
  id: string;
  title: string;
  username?: string;
  faviconDomain?: string;
  /** 0..1 — higher is a closer origin match. */
  matchQuality: number;
}

export interface VaultFieldsGetRequest {
  id: string;
  fields: ("username" | "password" | "totp")[];
  origin: string;
  reason: "autofill" | "copy";
}

export interface StatusEvent {
  locked: boolean;
  vpn: { stage: string; region?: string; rx: number; tx: number };
}

export const NM_MAX_MESSAGE_BYTES = 1024 * 1024; // 1 MiB hard cap on a single frame.
export const NM_HOST_NAME = "com.sentinel.host";
