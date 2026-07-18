// Table-driven autofill matching tests (node --test). Parity with the Rust
// origin_matches tests.
import { test } from "node:test";
import assert from "node:assert/strict";
import { urlMatches, originMatches, registrableDomain, rankCandidates, type SavedUrl } from "./matching.ts";

const D = (url: string): SavedUrl => ({ url, mode: "domain" });
const H = (url: string): SavedUrl => ({ url, mode: "host" });

const cases: [SavedUrl, string, boolean, string][] = [
  // domain matching across subdomains
  [D("https://example.com"), "https://example.com", true, "exact domain"],
  [D("https://example.com"), "https://login.example.com", true, "subdomain of domain"],
  [D("https://example.com"), "https://a.b.example.com", true, "deep subdomain"],
  [D("https://example.com"), "https://evil.com", false, "different domain"],
  [D("https://example.com"), "https://example.org", false, "different TLD"],
  [D("https://example.com"), "https://notexample.com", false, "suffix confusion"],
  [D("https://example.com"), "https://example.com.evil.com", false, "domain-in-subdomain attack"],
  // multi-label suffixes
  [D("https://example.co.uk"), "https://mail.example.co.uk", true, "co.uk subdomain"],
  [D("https://example.co.uk"), "https://example.com", false, "co.uk vs com"],
  [D("https://bbc.co.uk"), "https://www.bbc.co.uk", true, "bbc.co.uk"],
  // https downgrade
  [D("https://bank.com"), "http://bank.com", false, "https saved never fills http"],
  [D("http://legacy.local"), "https://legacy.local", true, "http saved may fill https"],
  // ports
  [H("https://localhost:8443"), "https://localhost:8443", true, "port exact"],
  [H("https://localhost:8443"), "https://localhost:9443", false, "port mismatch"],
  [H("https://localhost:8443"), "https://localhost", false, "port vs default"],
  [D("https://svc.com"), "https://svc.com:8443", false, "default vs explicit port"],
  // host-exact
  [H("https://www.example.com"), "https://www.example.com", true, "host exact match"],
  [H("https://www.example.com"), "https://api.example.com", false, "host exact rejects sibling"],
  [H("https://www.example.com"), "https://example.com", false, "host exact rejects apex"],
  // scheme variety
  [D("https://example.com"), "ftp://example.com", true, "non-http scheme same host domain"],
  // malformed
  [D("not a url"), "https://example.com", false, "malformed saved url"],
  [D("https://example.com"), "not a url", false, "malformed page origin"],
];

for (const [saved, page, want, name] of cases) {
  test(`urlMatches: ${name}`, () => {
    assert.equal(urlMatches(saved, page), want);
  });
}

test("registrableDomain handles common suffixes", () => {
  assert.equal(registrableDomain("login.example.co.uk"), "example.co.uk");
  assert.equal(registrableDomain("a.b.example.com"), "example.com");
  assert.equal(registrableDomain("example.com"), "example.com");
  assert.equal(registrableDomain("localhost"), "localhost");
});

test("cross-origin iframe is never matched", () => {
  const urls = [D("https://example.com")];
  // Page is example.com but the top frame is attacker.com → decline.
  assert.equal(originMatches(urls, "https://example.com", "https://attacker.com"), false);
  // Same-site top frame → allowed.
  assert.equal(originMatches(urls, "https://login.example.com", "https://example.com"), true);
});

test("ranking prefers host-exact then recency", () => {
  const items = [
    { urls: [D("https://example.com")], updatedAt: "2026-01-01" },
    { urls: [H("https://www.example.com")], updatedAt: "2025-01-01" },
  ];
  const ranked = rankCandidates(items, "https://www.example.com");
  assert.equal(ranked.length, 2);
  assert.equal(ranked[0].urls[0].mode, "host"); // host-exact wins despite being older
});

test("no cross-domain candidates leak into ranking", () => {
  const items = [{ urls: [D("https://other.com")], updatedAt: "2026-01-01" }];
  assert.equal(rankCandidates(items, "https://example.com").length, 0);
});
