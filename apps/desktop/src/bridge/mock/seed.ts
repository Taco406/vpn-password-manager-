// Typed view over the Rust-generated demo bundle (packages/shared/src/seed.json).
import seedJson from "@sentinel/shared/seed";

export interface SeedItem {
  id: string;
  type: "login" | "note" | "card" | "identity";
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

export const seed = seedJson as unknown as SeedBundle;
