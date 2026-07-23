// The Servers tab: the same fleet the desktop shows, driven by the provider tokens the desktop
// shared through the encrypted vault. Lists every Linode + Hetzner server and, where the desktop
// has a Netdata endpoint configured, live CPU / RAM / Disk / Load tiles read straight from the box.

import SwiftUI

@MainActor
final class ServersModel: ObservableObject {
    @Published var servers: [MonitoredServer] = []
    @Published var tiles: [String: NetdataTiles] = [:] // keyed by server.key
    @Published var loading = false
    @Published var error: String?

    private let netdata = NetdataClient()

    func refresh(tokens: ProviderTokens) async {
        loading = true
        error = nil
        var all: [MonitoredServer] = []
        var errs: [String] = []
        if !tokens.linode.isEmpty {
            do { all += try await LinodeClient.listServers(token: tokens.linode) }
            catch { errs.append("Linode: \(error.localizedDescription)") }
        }
        if !tokens.hetzner.isEmpty {
            do { all += try await HetznerClient.listServers(token: tokens.hetzner) }
            catch { errs.append("Hetzner: \(error.localizedDescription)") }
        }
        servers = all.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
        error = errs.isEmpty ? nil : errs.joined(separator: " · ")
        loading = false
        await refreshTiles(tokens: tokens)
    }

    func refreshTiles(tokens: ProviderTokens) async {
        let cfgs = NetdataEndpointCfg.map(fromJSON: tokens.netdataConfigJSON)
        for s in servers {
            guard let host = s.ipv4, let cfg = cfgs[s.key], cfg.enabled, !cfg.hasAuth else { continue }
            let t = await netdata.tiles(host: host, cfg: cfg)
            tiles[s.key] = t
        }
    }

    func hasNetdata(_ s: MonitoredServer, tokens: ProviderTokens) -> Bool {
        NetdataEndpointCfg.map(fromJSON: tokens.netdataConfigJSON)[s.key]?.enabled ?? false
    }
}

struct ServersView: View {
    @ObservedObject var vault: VaultStore
    @StateObject private var model = ServersModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    if !vault.providerTokens.hasAny {
                        Card {
                            VStack(alignment: .leading, spacing: 6) {
                                Text("No servers yet").font(.headline)
                                Text("Add your Linode or Hetzner Cloud API token on your computer (Settings → Servers). Once it syncs, your servers appear here automatically.")
                                    .font(.footnote).foregroundColor(.secondary)
                            }
                        }
                    }
                    if let e = model.error {
                        Card { Text(e).font(.footnote).foregroundColor(Color(hex: 0xF0A020)) }
                    }
                    ForEach(model.servers) { s in
                        ServerCard(server: s, tiles: model.tiles[s.key],
                                   hasNetdata: model.hasNetdata(s, tokens: vault.providerTokens))
                    }
                    if model.servers.isEmpty && vault.providerTokens.hasAny && !model.loading {
                        Card { Text("No servers found on your accounts.").font(.footnote).foregroundColor(.secondary) }
                    }
                }
                .padding(16)
            }
            .background(Color(hex: 0x0A0E14).ignoresSafeArea())
            .navigationTitle("Servers")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button {
                        Task { await model.refresh(tokens: vault.providerTokens) }
                    } label: {
                        if model.loading { ProgressView() } else { Image(systemName: "arrow.clockwise") }
                    }
                }
            }
            .task { await model.refresh(tokens: vault.providerTokens) }
            .refreshable { await model.refresh(tokens: vault.providerTokens) }
        }
    }
}

private struct ServerCard: View {
    let server: MonitoredServer
    let tiles: NetdataTiles?
    let hasNetdata: Bool

    var body: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(server.name).font(.headline)
                        Text("\(server.provider.rawValue) · \(server.region)")
                            .font(.caption).foregroundColor(.secondary)
                    }
                    Spacer()
                    StatusPill(status: server.status)
                }
                if let ip = server.ipv4 {
                    Text(ip).font(.caption.monospaced()).foregroundColor(.secondary)
                }
                if hasNetdata {
                    let t = tiles ?? NetdataTiles()
                    HStack(spacing: 8) {
                        Tile(label: "CPU", value: pct(t.cpu))
                        Tile(label: "RAM", value: pct(t.ram))
                        Tile(label: "Disk", value: pct(t.disk))
                        Tile(label: "Load", value: t.load.map { String(format: "%.2f", $0) } ?? "—")
                    }
                }
            }
        }
    }

    private func pct(_ v: Double?) -> String { v.map { String(format: "%.0f%%", $0) } ?? "—" }
}

private struct Tile: View {
    let label: String
    let value: String
    var body: some View {
        VStack(spacing: 2) {
            Text(label).font(.system(size: 10)).foregroundColor(.secondary)
            Text(value).font(.system(size: 15, weight: .semibold).monospaced())
                .foregroundColor(Color(hex: 0x22D3EE))
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 8)
        .background(Color(hex: 0x0A0E14))
        .cornerRadius(8)
    }
}

private struct StatusPill: View {
    let status: String
    var body: some View {
        let running = status == "running"
        Text(status)
            .font(.caption2)
            .padding(.horizontal, 8).padding(.vertical, 3)
            .background((running ? Color(hex: 0x2ED47A) : Color.gray).opacity(0.18))
            .foregroundColor(running ? Color(hex: 0x2ED47A) : .gray)
            .cornerRadius(20)
    }
}
