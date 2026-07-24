// Direct provider clients for the phone's Servers tab, plus the Netdata aggregation math ported
// 1:1 from crates/core/src/cloud/netdata.rs (the desktop's source of truth). Tokens come from the
// encrypted vault (the desktop shares them through the `northkey:system` settings item); the phone
// calls Linode / Hetzner / Netdata itself — the sync server is never involved in monitoring.

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

/// Power actions, mapped to each provider's endpoint by the clients.
enum PowerAction: String { case start, stop, reboot }

// MARK: - Linode

enum LinodeClient {
    private static func authed(_ method: String, _ path: String, token: String) async throws -> (Data, Int) {
        var req = URLRequest(url: URL(string: "https://api.linode.com/v4\(path)")!)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw MonitoringError.badResponse }
        return (data, http.statusCode)
    }

    static func listServers(token: String) async throws -> [MonitoredServer] {
        let (data, code) = try await authed("GET", "/linode/instances", token: token)
        guard (200..<300).contains(code) else { throw MonitoringError.http(code) }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let arr = obj["data"] as? [[String: Any]]
        else { throw MonitoringError.badResponse }
        return arr.map { s in
            let id = (s["id"] as? Int).map(String.init) ?? (s["id"] as? String ?? "")
            return MonitoredServer(
                provider: .linode, id: id,
                name: s["label"] as? String ?? "linode-\(id)",
                region: s["region"] as? String ?? "",
                status: s["status"] as? String ?? "unknown",
                ipv4: (s["ipv4"] as? [String])?.first)
        }
    }

    static func power(token: String, id: String, action: PowerAction) async throws {
        let path: String
        switch action {
        case .start: path = "/linode/instances/\(id)/boot"
        case .stop: path = "/linode/instances/\(id)/shutdown"
        case .reboot: path = "/linode/instances/\(id)/reboot"
        }
        let (_, code) = try await authed("POST", path, token: token)
        guard (200..<300).contains(code) else { throw MonitoringError.http(code) }
    }
}

// MARK: - Hetzner Cloud

enum HetznerClient {
    private static func authed(_ method: String, _ path: String, token: String) async throws -> (Data, Int) {
        var req = URLRequest(url: URL(string: "https://api.hetzner.cloud/v1\(path)")!)
        req.httpMethod = method
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        let (data, resp) = try await URLSession.shared.data(for: req)
        guard let http = resp as? HTTPURLResponse else { throw MonitoringError.badResponse }
        return (data, http.statusCode)
    }

    static func listServers(token: String) async throws -> [MonitoredServer] {
        let (data, code) = try await authed("GET", "/servers?per_page=50", token: token)
        guard (200..<300).contains(code) else { throw MonitoringError.http(code) }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let arr = obj["servers"] as? [[String: Any]]
        else { throw MonitoringError.badResponse }
        return arr.map { s in
            let id = (s["id"] as? Int).map(String.init) ?? (s["id"] as? String ?? "")
            let ipv4 = ((s["public_net"] as? [String: Any])?["ipv4"] as? [String: Any])?["ip"] as? String
            let region = ((s["datacenter"] as? [String: Any])?["location"] as? [String: Any])?["name"] as? String
            return MonitoredServer(
                provider: .hetzner, id: id,
                name: s["name"] as? String ?? "hetzner-\(id)",
                region: region ?? "",
                status: s["status"] as? String ?? "unknown",
                ipv4: ipv4)
        }
    }

    static func power(token: String, id: String, action: PowerAction) async throws {
        let path: String
        switch action {
        case .start: path = "/servers/\(id)/actions/poweron"
        case .stop: path = "/servers/\(id)/actions/shutdown"
        case .reboot: path = "/servers/\(id)/actions/reboot"
        }
        let (_, code) = try await authed("POST", path, token: token)
        guard (200..<300).contains(code) else { throw MonitoringError.http(code) }
    }
}

// MARK: - Netdata endpoint config (decoded from the desktop's synced JSON)

/// Per-server Netdata endpoint config, decoded from the desktop's synced `netdata_config` JSON
/// (a map of `"provider:id"` → `{enabled, port, https, hasAuth}`, camelCase like the Rust side).
struct NetdataEndpointCfg: Decodable {
    var enabled: Bool
    var port: Int
    var https: Bool
    var hasAuth: Bool
    /// Full `Authorization` header value for an auth-protected agent (v0.1.57), filled in from the
    /// synced `netdata_auth` map — NOT part of the `netdata_config` JSON, so it decodes to nil.
    var authHeader: String? = nil

    static func map(fromJSON json: String) -> [String: NetdataEndpointCfg] {
        guard !json.isEmpty, let data = json.data(using: .utf8) else { return [:] }
        return (try? JSONDecoder().decode([String: NetdataEndpointCfg].self, from: data)) ?? [:]
    }
}

// MARK: - Netdata aggregation math (pure — mirrors crates/core/src/cloud/netdata.rs, unit-tested)

/// A Netdata `/api/v1/data` response: `labels[0]` is "time" and each row is `[ts, v0, v1, …]`, so a
/// label at index i pairs with the row value at index i (the timestamp lives at index 0 of both).
struct NetdataData {
    let labels: [String]
    let rows: [[Double]]

    /// The newest row (by timestamp) — Netdata's default order is newest-first, but we don't rely
    /// on that: we pick the max-timestamp row so "current value" is always correct.
    var latest: [Double]? { rows.max { ($0.first ?? -.infinity) < ($1.first ?? -.infinity) } }

    /// Rows sorted oldest→newest, for charts.
    var ascending: [[Double]] { rows.sorted { ($0.first ?? 0) < ($1.first ?? 0) } }

    func index(of dim: String) -> Int? { labels.firstIndex(of: dim) }
}

enum NetdataMath {
    static func clampPct(_ v: Double) -> Double { min(max(v, 0), 100) }

    /// `system.cpu`: dimensions are per-mode percentages — total = row sum.
    static func cpuTotal(_ d: NetdataData) -> Double? {
        guard let row = d.latest else { return nil }
        return clampPct(row.dropFirst().reduce(0, +))
    }

    /// `system.ram`: used / total × 100.
    static func ramUsed(_ d: NetdataData) -> Double? {
        guard let row = d.latest, let i = d.index(of: "used"), i < row.count else { return nil }
        let total = row.dropFirst().reduce(0, +)
        guard total > 0 else { return nil }
        return clampPct(row[i] / total * 100)
    }

    /// `mem.swap`: used / (free + used) × 100. nil when the box has no swap.
    static func swapUsed(_ d: NetdataData) -> Double? {
        guard let row = d.latest, let f = d.index(of: "free"), let u = d.index(of: "used"),
              f < row.count, u < row.count else { return nil }
        let total = row[f] + row[u]
        guard total > 0 else { return nil }
        return clampPct(row[u] / total * 100)
    }

    /// `disk_space./`: used / (avail + used) × 100 (root reserve excluded, matching `df`).
    static func diskUsed(_ d: NetdataData) -> Double? {
        guard let row = d.latest, let a = d.index(of: "avail"), let u = d.index(of: "used"),
              a < row.count, u < row.count else { return nil }
        let denom = row[a] + row[u]
        guard denom > 0 else { return nil }
        return clampPct(row[u] / denom * 100)
    }

    /// The latest value of a named dimension (steal, running, uptime, "some 60"), optionally clamped.
    static func namedLatest(_ d: NetdataData, _ dim: String, clamp: Bool = false) -> Double? {
        guard let row = d.latest, let i = d.index(of: dim), i < row.count else { return nil }
        return clamp ? clampPct(row[i]) : row[i]
    }

    /// `system.load` → (load1, load5, load15).
    static func load(_ d: NetdataData) -> (Double?, Double?, Double?) {
        (namedLatest(d, "load1"), namedLatest(d, "load5"), namedLatest(d, "load15"))
    }

    /// A time series for one named dimension: `[(unixTs, value)]`, oldest→newest, |abs| optional.
    static func series(_ d: NetdataData, _ dim: String, abs useAbs: Bool = false) -> [(Double, Double)] {
        guard let i = d.index(of: dim) else { return [] }
        return d.ascending.compactMap { row in
            guard let ts = row.first, i < row.count else { return nil }
            return (ts, useAbs ? Swift.abs(row[i]) : row[i])
        }
    }
}

// MARK: - Netdata HTTP client

/// The single-value tiles for a server (nil = metric unavailable on this agent).
struct NetdataTiles {
    var cpu, ram, swap, disk: Double?
    var load1, load5, load15: Double?
    var steal, procs, uptimeSecs: Double?
    var psiCpu, psiMem, psiIo: Double?
}

struct NetdataAlarm: Identifiable {
    let id = UUID()
    let name: String
    let status: String
    let value: String
}

/// One labelled line for a chart.
struct ChartLine: Identifiable {
    let id = UUID()
    let label: String
    /// `(Date, value)` points, oldest→newest.
    let points: [(Date, Double)]
}

/// Reads Netdata's local HTTP API directly. Accepts the server's self-signed certificate for
/// read-only metrics (same posture as the desktop, which doesn't pin Netdata).
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

    private func base(_ host: String, _ cfg: NetdataEndpointCfg) -> String {
        "\(cfg.https ? "https" : "http")://\(host):\(cfg.port)"
    }

    /// A GET request carrying the synced `Authorization` header when the agent is auth-protected.
    private func request(_ url: URL, _ cfg: NetdataEndpointCfg) -> URLRequest {
        var req = URLRequest(url: url)
        if let auth = cfg.authHeader, !auth.isEmpty {
            req.setValue(auth, forHTTPHeaderField: "Authorization")
        }
        return req
    }

    /// Fetch one chart's raw `{labels, data}`.
    func fetch(host: String, cfg: NetdataEndpointCfg, chart: String, afterSecs: Int = 2, points: Int = 2)
        async throws -> NetdataData
    {
        let url = URL(string: "\(base(host, cfg))/api/v1/data?chart=\(chart)&after=-\(afterSecs)&points=\(points)&format=json&group=average")!
        let (data, resp) = try await session.data(for: request(url, cfg))
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
        return NetdataData(labels: labels, rows: rows)
    }

    /// All the single-value tiles. Each chart is fetched concurrently and independently, so one
    /// missing chart just leaves its tile nil instead of failing the whole set.
    func tiles(host: String, cfg: NetdataEndpointCfg) async -> NetdataTiles {
        func d(_ chart: String) async -> NetdataData? { try? await fetch(host: host, cfg: cfg, chart: chart) }
        async let cpu = d("system.cpu")
        async let ram = d("system.ram")
        async let swap = d("mem.swap")
        async let disk = d("disk_space./")
        async let load = d("system.load")
        async let procs = d("system.processes")
        async let uptime = d("system.uptime")
        async let psiCpu = d("system.cpu_some_pressure")
        async let psiMem = d("system.memory_some_pressure")
        async let psiIo = d("system.io_some_pressure")

        var t = NetdataTiles()
        if let x = await cpu { t.cpu = NetdataMath.cpuTotal(x); t.steal = NetdataMath.namedLatest(x, "steal", clamp: true) }
        if let x = await ram { t.ram = NetdataMath.ramUsed(x) }
        if let x = await swap { t.swap = NetdataMath.swapUsed(x) }
        if let x = await disk { t.disk = NetdataMath.diskUsed(x) }
        if let x = await load { let l = NetdataMath.load(x); t.load1 = l.0; t.load5 = l.1; t.load15 = l.2 }
        if let x = await procs { t.procs = NetdataMath.namedLatest(x, "running") }
        if let x = await uptime { t.uptimeSecs = NetdataMath.namedLatest(x, "uptime") }
        if let x = await psiCpu { t.psiCpu = NetdataMath.namedLatest(x, "some 60", clamp: true) }
        if let x = await psiMem { t.psiMem = NetdataMath.namedLatest(x, "some 60", clamp: true) }
        if let x = await psiIo { t.psiIo = NetdataMath.namedLatest(x, "some 60", clamp: true) }
        return t
    }

    /// A multi-line chart. `kind`: "net" (in/out bytes/s), "diskio" (read/write KiB/s→bytes/s),
    /// "load" (1m/5m/15m). Missing dims drop their line.
    func chart(host: String, cfg: NetdataEndpointCfg, kind: String) async -> [ChartLine] {
        let spec: (chart: String, dims: [(String, String)], scale: Double, abs: Bool)
        switch kind {
        case "net": spec = ("system.net", [("in", "InOctets"), ("out", "OutOctets")], 1, true)
        case "diskio": spec = ("system.io", [("read", "in"), ("write", "out")], 1024, true)
        case "load": spec = ("system.load", [("1m", "load1"), ("5m", "load5"), ("15m", "load15")], 1, false)
        default: return []
        }
        guard let d = try? await fetch(host: host, cfg: cfg, chart: spec.chart, afterSecs: 300, points: 90) else {
            return []
        }
        return spec.dims.compactMap { (label, dim) in
            let pts = NetdataMath.series(d, dim, abs: spec.abs)
            guard !pts.isEmpty else { return nil }
            return ChartLine(
                label: label,
                points: pts.map { (Date(timeIntervalSince1970: $0.0), $0.1 * spec.scale) })
        }
    }

    /// Active alarms from `/api/v1/alarms?active`.
    func alarms(host: String, cfg: NetdataEndpointCfg) async -> [NetdataAlarm] {
        guard let url = URL(string: "\(base(host, cfg))/api/v1/alarms?active"),
              let (data, resp) = try? await session.data(for: request(url, cfg)),
              let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let map = obj["alarms"] as? [String: Any]
        else { return [] }
        return map.compactMap { (id, raw) in
            guard let a = raw as? [String: Any] else { return nil }
            return NetdataAlarm(
                name: a["name"] as? String ?? id,
                status: a["status"] as? String ?? "UNKNOWN",
                value: a["value_string"] as? String ?? "")
        }
        .sorted { $0.name < $1.name }
    }
}
