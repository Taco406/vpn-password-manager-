// One server's full monitoring dashboard — the phone's match for the desktop's Netdata panel:
// a tile grid (CPU/RAM/Swap/Disk/Load 1-5-15/CPU-steal/PSI cpu-mem-io/processes/uptime), live
// Network / Disk-I/O / Load charts, active alarms, and power controls. Reads Netdata directly.

import SwiftUI
import Charts

@MainActor
final class ServerDetailModel: ObservableObject {
    @Published var tiles = NetdataTiles()
    @Published var netLines: [ChartLine] = []
    @Published var diskLines: [ChartLine] = []
    @Published var loadLines: [ChartLine] = []
    @Published var alarms: [NetdataAlarm] = []
    @Published var loading = false
    @Published var hasData = false
    @Published var powerMsg: String?

    private let client = NetdataClient()

    func refresh(host: String?, cfg: NetdataEndpointCfg?) async {
        guard let host, let cfg, cfg.enabled, !cfg.hasAuth else {
            hasData = false
            return
        }
        loading = true
        let t = await client.tiles(host: host, cfg: cfg)
        async let n = client.chart(host: host, cfg: cfg, kind: "net")
        async let d = client.chart(host: host, cfg: cfg, kind: "diskio")
        async let l = client.chart(host: host, cfg: cfg, kind: "load")
        async let a = client.alarms(host: host, cfg: cfg)
        tiles = t
        netLines = await n
        diskLines = await d
        loadLines = await l
        alarms = await a
        hasData = t.cpu != nil || !netLines.isEmpty || !loadLines.isEmpty
        loading = false
    }

    func power(server: MonitoredServer, tokens: ProviderTokens, action: PowerAction) async {
        powerMsg = "Sending \(action.rawValue)…"
        do {
            switch server.provider {
            case .linode:
                try await LinodeClient.power(token: tokens.linode, id: server.id, action: action)
            case .hetzner:
                try await HetznerClient.power(token: tokens.hetzner, id: server.id, action: action)
            }
            powerMsg = "\(action.rawValue.capitalized) requested — state updates shortly."
        } catch {
            powerMsg = error.localizedDescription
        }
    }
}

struct ServerDetailView: View {
    let server: MonitoredServer
    let cfg: NetdataEndpointCfg?
    @ObservedObject var vault: VaultStore
    @StateObject private var model = ServerDetailModel()
    @State private var confirmAction: PowerAction?

    var body: some View {
        ScrollView {
            VStack(spacing: 14) {
                header
                powerControls
                if cfg?.enabled == true && cfg?.hasAuth == false {
                    if model.hasData {
                        tileGrid
                        ChartCard(title: "Load average", lines: model.loadLines, format: .plain)
                        ChartCard(title: "Network", lines: model.netLines, format: .rate)
                        ChartCard(title: "Disk I/O", lines: model.diskLines, format: .rate)
                        alarmsCard
                    } else if model.loading {
                        Card { HStack { ProgressView(); Text("Reading Netdata…").font(.footnote).foregroundColor(.secondary) } }
                    } else {
                        Card {
                            Text("Couldn't reach Netdata on this server right now. If it's firewalled, open the port from the desktop app.")
                                .font(.footnote).foregroundColor(.secondary)
                        }
                    }
                } else if cfg?.hasAuth == true {
                    Card {
                        Text("This server's Netdata needs a username/password. Set it up on the desktop app — the phone can't hold that credential.")
                            .font(.footnote).foregroundColor(.secondary)
                    }
                } else {
                    Card {
                        Text("Live monitoring isn't set up for this server yet. Turn on Netdata for it from the desktop app.")
                            .font(.footnote).foregroundColor(.secondary)
                    }
                }
            }
            .padding(16)
            .readableColumn()
        }
        .background(Color(hex: 0x0A0E14).ignoresSafeArea())
        .navigationTitle(server.name)
        .navigationBarTitleDisplayMode(.inline)
        .refreshable { await model.refresh(host: server.ipv4, cfg: cfg) }
        .task {
            // Poll while the dashboard is on screen; the task is cancelled on disappear.
            while !Task.isCancelled {
                await model.refresh(host: server.ipv4, cfg: cfg)
                try? await Task.sleep(nanoseconds: 6_000_000_000)
            }
        }
    }

    private var header: some View {
        Card {
            VStack(alignment: .leading, spacing: 4) {
                HStack {
                    Text("\(server.provider.rawValue) · \(server.region)")
                        .font(.caption).foregroundColor(.secondary)
                    Spacer()
                    StatusPill(status: server.status)
                }
                if let ip = server.ipv4 {
                    Text(ip).font(.subheadline.monospaced()).foregroundColor(.secondary)
                }
            }
        }
    }

    private var powerControls: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                Text("Power").font(.subheadline.bold())
                HStack(spacing: 10) {
                    powerButton(.start, "Start", "play.fill", Color(hex: 0x2ED47A))
                    powerButton(.reboot, "Reboot", "arrow.clockwise", Color(hex: 0x22D3EE))
                    powerButton(.stop, "Stop", "stop.fill", Color(hex: 0xF0A020))
                }
                if let m = model.powerMsg {
                    Text(m).font(.caption).foregroundColor(.secondary)
                }
            }
        }
        .confirmationDialog(
            "\(confirmAction?.rawValue.capitalized ?? "") \(server.name)?",
            isPresented: Binding(get: { confirmAction != nil }, set: { if !$0 { confirmAction = nil } }),
            titleVisibility: .visible
        ) {
            if let a = confirmAction {
                Button(a == .stop ? "Stop server" : a.rawValue.capitalized, role: a == .stop ? .destructive : nil) {
                    Task { await model.power(server: server, tokens: vault.providerTokens, action: a) }
                    confirmAction = nil
                }
            }
        }
    }

    private func powerButton(_ action: PowerAction, _ label: String, _ icon: String, _ color: Color) -> some View {
        Button { confirmAction = action } label: {
            Label(label, systemImage: icon)
                .font(.caption.bold())
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .background(color.opacity(0.15))
                .foregroundColor(color)
                .cornerRadius(8)
        }
    }

    private var tileGrid: some View {
        LazyVGrid(columns: [GridItem(.adaptive(minimum: 92), spacing: 8)], spacing: 8) {
            Tile("CPU", pct(model.tiles.cpu), tone: tone(model.tiles.cpu, 75, 90))
            Tile("RAM", pct(model.tiles.ram), tone: tone(model.tiles.ram, 80, 92))
            Tile("Swap", pct(model.tiles.swap), tone: tone(model.tiles.swap, 25, 60))
            Tile("Disk /", pct(model.tiles.disk), tone: tone(model.tiles.disk, 80, 92))
            Tile("Load 1m", model.tiles.load1.map { String(format: "%.2f", $0) } ?? "—", tone: .plain)
            Tile("Load 5m", model.tiles.load5.map { String(format: "%.2f", $0) } ?? "—", tone: .plain)
            Tile("Load 15m", model.tiles.load15.map { String(format: "%.2f", $0) } ?? "—", tone: .plain)
            Tile("CPU steal", pct(model.tiles.steal, 1), tone: tone(model.tiles.steal, 5, 20))
            Tile("Procs", model.tiles.procs.map { String(format: "%.0f", $0) } ?? "—", tone: .plain)
            Tile("Uptime", fmtUptime(model.tiles.uptimeSecs), tone: .plain)
            Tile("PSI cpu", pct(model.tiles.psiCpu, 1), tone: tone(model.tiles.psiCpu, 10, 40))
            Tile("PSI mem", pct(model.tiles.psiMem, 1), tone: tone(model.tiles.psiMem, 5, 20))
            Tile("PSI io", pct(model.tiles.psiIo, 1), tone: tone(model.tiles.psiIo, 10, 40))
        }
    }

    private var alarmsCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 6) {
                Text("Alarms").font(.subheadline.bold())
                if model.alarms.isEmpty {
                    Label("No active alarms", systemImage: "checkmark.seal.fill")
                        .font(.caption).foregroundColor(Color(hex: 0x2ED47A))
                } else {
                    ForEach(model.alarms) { a in
                        HStack {
                            Circle().fill(a.status == "CRITICAL" ? Color(hex: 0xF87171) : Color(hex: 0xF0A020))
                                .frame(width: 7, height: 7)
                            Text(a.name).font(.caption)
                            Spacer()
                            Text(a.value).font(.caption.monospaced()).foregroundColor(.secondary)
                        }
                    }
                }
            }
        }
    }

    private func pct(_ v: Double?, _ digits: Int = 0) -> String {
        v.map { String(format: "%.\(digits)f%%", $0) } ?? "—"
    }
}

// MARK: - Tiles

enum Tone { case plain, ok, warn, danger }

func tone(_ v: Double?, _ warn: Double, _ danger: Double) -> Tone {
    guard let v else { return .plain }
    if v >= danger { return .danger }
    if v >= warn { return .warn }
    return .ok
}

private struct Tile: View {
    let label: String
    let value: String
    let tone: Tone
    init(_ label: String, _ value: String, tone: Tone) {
        self.label = label
        self.value = value
        self.tone = tone
    }
    private var color: Color {
        switch tone {
        case .plain: return Color(hex: 0x22D3EE)
        case .ok: return Color(hex: 0x2ED47A)
        case .warn: return Color(hex: 0xF0A020)
        case .danger: return Color(hex: 0xF87171)
        }
    }
    var body: some View {
        VStack(spacing: 3) {
            Text(label.uppercased()).font(.system(size: 9)).foregroundColor(.secondary)
            Text(value).font(.system(size: 15, weight: .semibold).monospaced()).foregroundColor(color)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 10)
        .background(Color(hex: 0x0F141C))
        .cornerRadius(10)
    }
}

// MARK: - Charts

enum ChartFormat { case plain, rate }

private struct ChartCard: View {
    let title: String
    let lines: [ChartLine]
    let format: ChartFormat
    private let palette = [Color(hex: 0x22D3EE), Color(hex: 0xF472B6), Color(hex: 0xA78BFA)]

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text(title).font(.subheadline.bold())
                    Spacer()
                    ForEach(Array(lines.enumerated()), id: \.offset) { i, line in
                        HStack(spacing: 3) {
                            Circle().fill(palette[i % palette.count]).frame(width: 6, height: 6)
                            Text(line.label).font(.caption2).foregroundColor(.secondary)
                        }
                    }
                }
                if lines.contains(where: { $0.points.count >= 2 }) {
                    Chart {
                        ForEach(Array(lines.enumerated()), id: \.offset) { i, line in
                            ForEach(line.points.indices, id: \.self) { p in
                                LineMark(
                                    x: .value("t", line.points[p].0),
                                    y: .value("v", line.points[p].1),
                                    series: .value("s", line.label)
                                )
                                .foregroundStyle(palette[i % palette.count])
                                .interpolationMethod(.catmullRom)
                            }
                        }
                    }
                    .chartYAxis {
                        AxisMarks { value in
                            AxisGridLine()
                            AxisValueLabel {
                                if let d = value.as(Double.self) {
                                    Text(format == .rate ? fmtRate(d) : fmtPlain(d))
                                }
                            }
                        }
                    }
                    .chartXAxis(.hidden)
                    .frame(height: 130)
                } else {
                    Text("waiting for data…").font(.caption).foregroundColor(.secondary)
                        .frame(height: 60)
                }
            }
        }
    }
}

// MARK: - Formatting helpers

func fmtUptime(_ secs: Double?) -> String {
    guard let s = secs, s > 0 else { return "—" }
    let d = Int(s) / 86400
    let h = (Int(s) % 86400) / 3600
    let m = (Int(s) % 3600) / 60
    if d > 0 { return "\(d)d \(h)h" }
    if h > 0 { return "\(h)h \(m)m" }
    return "\(m)m"
}

/// Bytes/second → a human string (Netdata network/disk throughput).
func fmtRate(_ bytesPerSec: Double) -> String {
    let v = bytesPerSec
    if v >= 1e9 { return String(format: "%.1f GB/s", v / 1e9) }
    if v >= 1e6 { return String(format: "%.1f MB/s", v / 1e6) }
    if v >= 1e3 { return String(format: "%.0f KB/s", v / 1e3) }
    return String(format: "%.0f B/s", v)
}

func fmtPlain(_ v: Double) -> String {
    v >= 1000 ? String(format: "%.1fk", v / 1000) : String(format: "%.1f", v)
}
