// The Servers tab: the same fleet the desktop shows, driven by the provider tokens the desktop
// shared through the encrypted vault. Lists every Linode + Hetzner server; tapping one opens a
// full monitoring dashboard (ServerDetailView) with live Netdata tiles, charts, alarms, and power.

import SwiftUI

@MainActor
final class ServersModel: ObservableObject {
    @Published var servers: [MonitoredServer] = []
    @Published var loading = false
    @Published var error: String?

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
    }

    func netdataCfg(for server: MonitoredServer, tokens: ProviderTokens) -> NetdataEndpointCfg? {
        NetdataEndpointCfg.map(fromJSON: tokens.netdataConfigJSON)[server.key]
    }
}

struct ServersView: View {
    @ObservedObject var vault: VaultStore
    @StateObject private var model = ServersModel()

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 12) {
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
                        NavigationLink {
                            ServerDetailView(server: s, cfg: model.netdataCfg(for: s, tokens: vault.providerTokens), vault: vault)
                        } label: {
                            ServerRow(server: s, hasNetdata: model.netdataCfg(for: s, tokens: vault.providerTokens)?.enabled ?? false)
                        }
                        .buttonStyle(.plain)
                    }
                    if model.servers.isEmpty && vault.providerTokens.hasAny && !model.loading {
                        Card { Text("No servers found on your accounts.").font(.footnote).foregroundColor(.secondary) }
                    }
                }
                .padding(16)
                .readableColumn()
            }
            .background(Color(hex: 0x0A0E14).ignoresSafeArea())
            .navigationTitle("Servers")
            .toolbar {
                ToolbarItem(placement: .topBarTrailing) {
                    Button { Task { await reload() } } label: {
                        if model.loading { ProgressView() } else { Image(systemName: "arrow.clockwise") }
                    }
                }
            }
            .task { await reload() }
            .refreshable { await reload() }
        }
    }

    /// Pull the vault first so a token the desktop just shared (e.g. a back-filled Hetzner token)
    /// shows up here without visiting the Vault tab, then list the servers.
    private func reload() async {
        try? await vault.pull()
        await model.refresh(tokens: vault.providerTokens)
    }
}

private struct ServerRow: View {
    let server: MonitoredServer
    let hasNetdata: Bool

    var body: some View {
        Card {
            HStack {
                VStack(alignment: .leading, spacing: 3) {
                    Text(server.name).font(.headline)
                    Text("\(server.provider.rawValue) · \(server.region)")
                        .font(.caption).foregroundColor(.secondary)
                    if let ip = server.ipv4 {
                        Text(ip).font(.caption.monospaced()).foregroundColor(.secondary)
                    }
                }
                Spacer()
                VStack(alignment: .trailing, spacing: 6) {
                    StatusPill(status: server.status)
                    if hasNetdata {
                        Label("Live", systemImage: "waveform.path.ecg")
                            .font(.caption2).foregroundColor(Color(hex: 0x22D3EE))
                    }
                    Image(systemName: "chevron.right").font(.caption2).foregroundColor(.secondary)
                }
            }
        }
    }
}

struct StatusPill: View {
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
