// Direct provider clients for the phone's Servers tab. The tokens come from the encrypted vault
// (the desktop shares them through the `northkey:system` settings item — see VaultStore), and the
// phone calls Linode / Hetzner / Netdata itself, exactly like the desktop. The sync server is never
// involved in monitoring and never sees these tokens in plaintext.
//
// The Netdata aggregation math mirrors crates/core/src/cloud/netdata.rs 1:1 (the desktop's source
// of truth): system.cpu = row sum, system.ram = used/total, disk_space./ = used/(avail+used),
// system.load = load1.

import Foundation

/// One server as the Servers tab shows it, from either provider.
struct MonitoredServer: Identifiable {
    enum Provider: String { case linode, hetzner }
    let provider: Provider
    let id: String
    let name: String
    let region: String
    let status: String
    let ipv4: String?
    var key: String { "\(provider.rawValue):\(id)" }
}

/// The single-value Netdata tiles the phone shows for a server (nil = metric unavailable).
struct NetdataTiles {
    var cpu: Double?
    var ram: Double?
    var disk: Double?
    var load: Double?
}

enum MonitoringError: Error, LocalizedError {
    case http(Int)
    case badResponse
    var errorDescription: String? {
        switch self {
        case .http(let c): return "Provider API returned HTTP \(c)."
        case .badResponse: return "Unexpected response from the provider."
        }
    }
}

/// Linode: list the account's instances (bearer token from the synced vault).
enum LinodeClient {
    static func listServers(token: String) async throws -> [MonitoredServer] {
        var req = URLRequest(url: URL(string: "https://api.linode.com/v4/linode/instances")!)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw MonitoringError.badResponse }
        guard (200..<300).contains(http.statusCode) else { throw MonitoringError.http(http.statusCode) }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let arr = obj["data"] as? [[String: Any]]
        else { throw MonitoringError.badResponse }
        return arr.map { s in
            let id = (s["id"] as? Int).map(String.init) ?? (s["id"] as? String ?? "")
            let ipv4 = (s["ipv4"] as? [String])?.first
            return MonitoredServer(
                provider: .linode,
                id: id,
                name: s["label"] as? String ?? "linode-\(id)",
                region: s["region"] as? String ?? "",
                status: s["status"] as? String ?? "unknown",
                ipv4: ipv4)
        }
    }
}

/// Hetzner Cloud: list the project's servers (bearer token from the synced vault).
enum HetznerClient {
    static func listServers(token: String) async throws -> [MonitoredServer] {
        var req = URLRequest(url: URL(string: "https://api.hetzner.cloud/v1/servers?per_page=50")!)
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw MonitoringError.badResponse }
        guard (200..<300).contains(http.statusCode) else { throw MonitoringError.http(http.statusCode) }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let arr = obj["servers"] as? [[String: Any]]
        else { throw MonitoringError.badResponse }
        return arr.map { s in
            let id = (s["id"] as? Int).map(String.init) ?? (s["id"] as? String ?? "")
            let publicNet = s["public_net"] as? [String: Any]
            let ipv4 = (publicNet?["ipv4"] as? [String: Any])?["ip"] as? String
            let region = ((s["datacenter"] as? [String: Any])?["location"] as? [String: Any])?["name"] as? String
            return MonitoredServer(
                provider: .hetzner,
                id: id,
                name: s["name"] as? String ?? "hetzner-\(id)",
                region: region ?? "",
                status: s["status"] as? String ?? "unknown",
                ipv4: ipv4)
        }
    }
}

/// Per-server Netdata endpoint config, decoded from the desktop's synced `netdata_config` JSON
/// (a map of `"provider:id"` → `{enabled, port, https, hasAuth}`, camelCase like the Rust side).
struct NetdataEndpointCfg: Decodable {
    var enabled: Bool
    var port: Int
    var https: Bool
    var hasAuth: Bool

    static func map(fromJSON json: String) -> [String: NetdataEndpointCfg] {
        guard !json.isEmpty, let data = json.data(using: .utf8) else { return [:] }
        return (try? JSONDecoder().decode([String: NetdataEndpointCfg].self, from: data)) ?? [:]
    }
}

/// Reads Netdata's local HTTP API directly. Accepts the server's self-signed certificate for
/// read-only metrics (same posture as the desktop, which doesn't pin Netdata) — no plaintext
/// secret ever rides this connection; it only fetches public utilization numbers.
final class NetdataClient: NSObject, URLSessionDelegate {
    private lazy var session: URLSession =
        URLSession(configuration: .ephemeral, delegate: self, delegateQueue: nil)

    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        if challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
           let trust = challenge.protectionSpace.serverTrust {
            completionHandler(.useCredential, URLCredential(trust: trust))
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }

    private func base(host: String, cfg: NetdataEndpointCfg) -> String {
        "\(cfg.https ? "https" : "http")://\(host):\(cfg.port)"
    }

    /// Fetch one chart and return its raw `{labels, data}` — labels[0] is "time"; each data row is
    /// `[ts, v0, v1, …]`, so label index i ↔ value index i (ts included here, unlike the Rust
    /// `NetdataSeries` which strips it).
    private func fetchChart(host: String, cfg: NetdataEndpointCfg, chart: String) async throws
        -> (labels: [String], rows: [[Double]])
    {
        let url = URL(string: "\(base(host: host, cfg: cfg))/api/v1/data?chart=\(chart)&after=-2&points=2&format=json&group=average")!
        let (data, resp) = try await session.data(from: url)
        guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            throw MonitoringError.badResponse
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let labels = obj["labels"] as? [String],
              let rawRows = obj["data"] as? [[Any]]
        else { throw MonitoringError.badResponse }
        let rows: [[Double]] = rawRows.map { row in
            row.map { ($0 as? Double) ?? ($0 as? Int).map(Double.init) ?? 0 }
        }
        return (labels, rows)
    }

    /// The last-value single tiles for a server. Each metric is fetched independently, so one
    /// missing chart just leaves that tile nil instead of failing the whole set.
    func tiles(host: String, cfg: NetdataEndpointCfg) async -> NetdataTiles {
        var t = NetdataTiles()
        t.cpu = try? await lastCpu(host: host, cfg: cfg)
        t.ram = try? await lastRam(host: host, cfg: cfg)
        t.disk = try? await lastDisk(host: host, cfg: cfg)
        t.load = try? await lastLoad(host: host, cfg: cfg)
        return t
    }

    // Aggregations mirror crates/core/src/cloud/netdata.rs. `row[0]` is the timestamp; the metric
    // values start at index 1, so a label at index i pairs with row value at index i.

    private func lastCpu(host: String, cfg: NetdataEndpointCfg) async throws -> Double {
        let (_, rows) = try await fetchChart(host: host, cfg: cfg, chart: "system.cpu")
        guard let row = rows.last else { throw MonitoringError.badResponse }
        let sum = row.dropFirst().reduce(0, +)
        return min(max(sum, 0), 100)
    }

    private func lastRam(host: String, cfg: NetdataEndpointCfg) async throws -> Double {
        let (labels, rows) = try await fetchChart(host: host, cfg: cfg, chart: "system.ram")
        guard let row = rows.last, let usedIdx = labels.firstIndex(of: "used") else {
            throw MonitoringError.badResponse
        }
        let total = row.dropFirst().reduce(0, +)
        guard total > 0, usedIdx < row.count else { throw MonitoringError.badResponse }
        return min(max(row[usedIdx] / total * 100, 0), 100)
    }

    private func lastDisk(host: String, cfg: NetdataEndpointCfg) async throws -> Double {
        let (labels, rows) = try await fetchChart(host: host, cfg: cfg, chart: "disk_space./")
        guard let row = rows.last,
              let availIdx = labels.firstIndex(of: "avail"), let usedIdx = labels.firstIndex(of: "used"),
              availIdx < row.count, usedIdx < row.count
        else { throw MonitoringError.badResponse }
        let denom = row[availIdx] + row[usedIdx]
        guard denom > 0 else { throw MonitoringError.badResponse }
        return min(max(row[usedIdx] / denom * 100, 0), 100)
    }

    private func lastLoad(host: String, cfg: NetdataEndpointCfg) async throws -> Double {
        let (_, rows) = try await fetchChart(host: host, cfg: cfg, chart: "system.load")
        guard let row = rows.last, row.count >= 2 else { throw MonitoringError.badResponse }
        return row[1] // load1 is the first value after the timestamp
    }
}
