// Autofill origin matching. Mirrors the authoritative Rust `vault::session::
// origin_matches` (the desktop re-checks before releasing any field). Rules:
//  1. https-saved never fills on http (no downgrade);
//  2. non-default ports must match exactly;
//  3. "host" mode = exact host; "domain" mode = registrable-domain equality;
//  4. never fill in cross-origin iframes (caller passes topOrigin);
//  5. fill only on explicit user gesture (enforced by the content script).

export type UrlMode = "domain" | "host";
export interface SavedUrl {
  url: string;
  mode: UrlMode;
}

// A pragmatic subset of multi-label public suffixes — identical to the Rust list so
// both sides agree on the registrable domain.
const TWO_LABEL_SUFFIXES = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "co.jp", "or.jp", "ne.jp", "com.au", "net.au",
  "org.au", "co.nz", "com.br", "com.mx", "co.in", "co.za", "com.sg",
]);

interface Origin {
  scheme: string;
  host: string;
  port: string | null; // null = scheme default
}

function parseOrigin(input: string): Origin | null {
  try {
    const u = new URL(input);
    return { scheme: u.protocol.replace(":", ""), host: u.hostname.toLowerCase(), port: u.port || null };
  } catch {
    return null;
  }
}

export function registrableDomain(host: string): string {
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  const last2 = labels.slice(-2).join(".");
  if (TWO_LABEL_SUFFIXES.has(last2) && labels.length >= 3) return labels.slice(-3).join(".");
  return last2;
}

/** Does a single saved URL match the page origin? */
export function urlMatches(saved: SavedUrl, pageOrigin: string): boolean {
  const s = parseOrigin(saved.url);
  const p = parseOrigin(pageOrigin);
  if (!s || !p) return false;
  if (s.scheme === "https" && p.scheme === "http") return false; // no downgrade
  if (s.port !== p.port) return false; // ports must match
  if (saved.mode === "host") return s.host === p.host;
  return registrableDomain(s.host) === registrableDomain(p.host);
}

/** Does any of an item's URLs match, respecting the cross-origin-iframe rule? */
export function originMatches(urls: SavedUrl[], pageOrigin: string, topOrigin?: string): boolean {
  // Never offer autofill inside a cross-origin iframe.
  if (topOrigin && !sameSite(pageOrigin, topOrigin)) return false;
  return urls.some((u) => urlMatches(u, pageOrigin));
}

function sameSite(a: string, b: string): boolean {
  const oa = parseOrigin(a);
  const ob = parseOrigin(b);
  if (!oa || !ob) return false;
  return registrableDomain(oa.host) === registrableDomain(ob.host);
}

/** Rank candidates: host-exact first, then shallower subdomains, then by recency. */
export function rankCandidates<T extends { urls: SavedUrl[]; updatedAt?: string }>(
  items: T[],
  pageOrigin: string,
  topOrigin?: string,
): T[] {
  const p = parseOrigin(pageOrigin);
  return items
    .filter((i) => originMatches(i.urls, pageOrigin, topOrigin))
    .sort((a, b) => {
      const score = (it: T) => {
        const exact = it.urls.some((u) => u.mode === "host" && parseOrigin(u.url)?.host === p?.host);
        return exact ? 0 : 1;
      };
      const s = score(a) - score(b);
      if (s !== 0) return s;
      return (b.updatedAt ?? "").localeCompare(a.updatedAt ?? "");
    });
}
