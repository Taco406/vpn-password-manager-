// Typed view over the Rust-generated demo bundle (packages/shared/src/seed.json).
import seedJson from "@sentinel/shared/seed";

/** Safe passkey metadata shown in the mock — mirrors the backend's PasskeyOut. No key. */
export interface SeedPasskey {
  rpId: string;
  rpName?: string;
  userName: string;
  userDisplayName?: string;
  credentialId: string;
  algorithm: number;
  signCount: number;
}

export interface SeedItem {
  id: string;
  type: "login" | "note" | "card" | "identity" | "passkey";
  title: string;
  username: string | null;
  password: string | null;
  tags: string[];
  faviconDomain: string | null;
  hasTotp: boolean;
  totpUri: string | null;
  urls: string[];
  notes: string | null;
  updatedAt: string;
  passwordChangedAt: string | null;
  /** Present only for passkey items. Placeholder metadata; never a real key. */
  passkey?: SeedPasskey;
}

export interface SeedRegion {
  id: string;
  label: string;
  country: string;
  lat: number;
  lon: number;
  latencyMs: number;
  medianDownMbps: number;
}

export interface SeedInstanceType {
  id: string;
  label: string;
  vcpus: number;
  memoryMb: number;
  hourlyUsd: number;
}

export interface SeedSession {
  id: string;
  region: string;
  instanceType: string;
  startedAt: string;
  endedAt: string;
  bytesRx: number;
  bytesTx: number;
  costUsd: number;
  peakCpuPct: number;
  downMbps: number;
  upMbps: number;
}

export interface SeedProfile {
  id: string;
  name: string;
  regionId: string;
  instanceType: string;
  killSwitch: boolean;
  splitTunnelApps: string[];
  ssidTriggers: string[];
}

export interface SeedBundle {
  generatedNote: string;
  items: SeedItem[];
  regions: SeedRegion[];
  instanceTypes: SeedInstanceType[];
  history: SeedSession[];
  profiles: SeedProfile[];
}

const bundle = seedJson as unknown as SeedBundle;

/**
 * One sample passkey so the vault display + screenshots have a passkey to show. Placeholder
 * metadata only — no real key material lives in the mock. Appended here rather than in the
 * Rust-generated seed.json so it survives regeneration.
 */
const samplePasskey: SeedItem = {
  id: "0e0e0e0e-0e0e-0e0e-0e0e-0e0e0e0e0e0e",
  type: "passkey",
  title: "octocat @ github.com",
  username: "octocat",
  password: null,
  tags: ["passkey"],
  faviconDomain: "github.com",
  hasTotp: false,
  totpUri: null,
  urls: [],
  notes: null,
  updatedAt: "2026-06-05T12:00:00Z",
  passwordChangedAt: null,
  passkey: {
    rpId: "github.com",
    rpName: "GitHub",
    userName: "octocat",
    userDisplayName: "The Octocat",
    credentialId: "AAECAwQFBgcICQoLDA0ODw",
    algorithm: -7,
    signCount: 0,
  },
};

export const seed: SeedBundle = { ...bundle, items: [...bundle.items, samplePasskey] };
