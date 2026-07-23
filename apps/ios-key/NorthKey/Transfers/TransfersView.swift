// The Transfers tab: send a file to the user's other devices and receive files they send here.
// Files are sealed/opened on-device with the vault key (SFIL blob) and relayed through the sync
// server as opaque ciphertext — the same end-to-end path the desktop uses.

import SwiftUI
import UniformTypeIdentifiers

@MainActor
final class TransfersModel: ObservableObject {
    @Published var rows: [ApiClient.TransferRow] = []
    @Published var devices: [ApiClient.DeviceRow] = []
    @Published var busy = false
    @Published var status: String?
    /// A decrypted file waiting to be saved/shared (written to a temp URL for the share sheet).
    @Published var shareURL: URL?

    private static let maxBytes = 25 * 1024 * 1024

    func refresh() async {
        do {
            async let r = ApiClient.shared.listTransfers()
            async let d = ApiClient.shared.listDevices()
            rows = try await r
            devices = try await d
        } catch {
            status = ApiError.describe(error)
        }
    }

    func send(fileURL: URL, recipientDeviceId: String?, vaultKey: Data) async {
        busy = true
        status = "Encrypting and sending…"
        defer { busy = false }
        let scoped = fileURL.startAccessingSecurityScopedResource()
        defer { if scoped { fileURL.stopAccessingSecurityScopedResource() } }
        do {
            let bytes = try Data(contentsOf: fileURL)
            guard !bytes.isEmpty else { status = "That file is empty."; return }
            guard bytes.count <= Self.maxBytes else {
                status = "That file is larger than the 25 MB limit."; return
            }
            let name = fileURL.lastPathComponent
            let meta = VaultCrypto.FileMeta(filename: name, mime: Self.mime(for: fileURL))
            let blob = try VaultCrypto.sealFileBlob(vaultKey: vaultKey, meta: meta, bytes: bytes)
            guard blob.count <= Self.maxBytes else {
                status = "That file is too large to send once encrypted."; return
            }
            _ = try await ApiClient.shared.createTransfer(
                recipientDeviceId: recipientDeviceId, sizeBytes: bytes.count, ciphertext: blob)
            status = "Sent \"\(name)\"."
            await refresh()
        } catch {
            status = ApiError.describe(error)
        }
    }

    func receive(_ row: ApiClient.TransferRow, vaultKey: Data) async {
        busy = true
        status = "Downloading and decrypting…"
        defer { busy = false }
        do {
            let ct = try await ApiClient.shared.downloadTransfer(id: row.id)
            let (meta, bytes) = try VaultCrypto.openFileBlob(vaultKey: vaultKey, blob: ct)
            let safeName = (meta.filename as NSString).lastPathComponent
            let url = FileManager.default.temporaryDirectory
                .appendingPathComponent(safeName.isEmpty ? "download.bin" : safeName)
            try bytes.write(to: url, options: .atomic)
            shareURL = url
            status = nil
        } catch {
            status = ApiError.describe(error)
        }
    }

    func delete(_ row: ApiClient.TransferRow) async {
        do {
            try await ApiClient.shared.deleteTransfer(id: row.id)
            await refresh()
        } catch {
            status = ApiError.describe(error)
        }
    }

    func deviceName(_ id: String?) -> String {
        guard let id else { return "All my devices" }
        if let d = devices.first(where: { $0.id == id }) {
            return d.name + ((d.current ?? false) ? " (this iPhone)" : "")
        }
        return String(id.prefix(8))
    }

    private static func mime(for url: URL) -> String {
        if let t = UTType(filenameExtension: url.pathExtension)?.preferredMIMEType { return t }
        return "application/octet-stream"
    }
}

struct TransfersView: View {
    @ObservedObject var vault: VaultStore
    @StateObject private var model = TransfersModel()
    @State private var picking = false
    @State private var recipient: String? // nil = all my devices

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(spacing: 14) {
                    sendCard
                    incomingCard
                    outgoingCard
                    if let s = model.status {
                        Text(s).font(.footnote).foregroundColor(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                }
                .padding(16)
                .readableColumn()
            }
            .background(Color(hex: 0x0A0E14).ignoresSafeArea())
            .navigationTitle("Transfers")
            .task { await model.refresh() }
            .refreshable { await model.refresh() }
            .fileImporter(isPresented: $picking, allowedContentTypes: [.data, .item]) { result in
                guard case .success(let url) = result, let key = vault.currentVaultKey else { return }
                Task { await model.send(fileURL: url, recipientDeviceId: recipient, vaultKey: key) }
            }
            .sheet(item: Binding(get: { model.shareURL.map { ShareItem(url: $0) } },
                                 set: { model.shareURL = $0?.url })) { item in
                ShareSheet(items: [item.url])
            }
        }
    }

    private var sendCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 10) {
                Text("Send a file").font(.headline)
                Text("Encrypted on this phone with your vault key before it leaves. Up to 25 MB.")
                    .font(.footnote).foregroundColor(.secondary)
                Picker("To", selection: $recipient) {
                    Text("All my devices").tag(String?.none)
                    ForEach(model.devices.filter { !($0.current ?? false) }) { d in
                        Text("\(d.name) · \(d.platform)").tag(String?.some(d.id))
                    }
                }
                .pickerStyle(.menu)
                Button {
                    picking = true
                } label: {
                    Label("Choose a file", systemImage: "paperclip")
                }
                .disabled(model.busy)
            }
        }
    }

    private var incomingCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                Text("Incoming").font(.headline)
                let incoming = model.rows.filter { !$0.outgoing }
                if incoming.isEmpty {
                    Text("Nothing waiting for this device.").font(.footnote).foregroundColor(.secondary)
                } else {
                    ForEach(incoming) { row in
                        TransferRowView(
                            title: "from \(model.deviceName(row.senderDeviceId))",
                            row: row, busy: model.busy,
                            onPrimary: {
                                guard let key = vault.currentVaultKey else { return }
                                Task { await model.receive(row, vaultKey: key) }
                            },
                            primaryLabel: "Save",
                            onDelete: { Task { await model.delete(row) } })
                    }
                }
            }
        }
    }

    private var outgoingCard: some View {
        Card {
            VStack(alignment: .leading, spacing: 8) {
                Text("Sent").font(.headline)
                let outgoing = model.rows.filter { $0.outgoing }
                if outgoing.isEmpty {
                    Text("You haven't sent anything yet.").font(.footnote).foregroundColor(.secondary)
                } else {
                    ForEach(outgoing) { row in
                        TransferRowView(
                            title: "to \(model.deviceName(row.recipientDeviceId))",
                            row: row, busy: model.busy,
                            onPrimary: nil, primaryLabel: nil,
                            onDelete: { Task { await model.delete(row) } })
                    }
                }
            }
        }
    }
}

private struct TransferRowView: View {
    let title: String
    let row: ApiClient.TransferRow
    let busy: Bool
    let onPrimary: (() -> Void)?
    let primaryLabel: String?
    let onDelete: () -> Void

    var body: some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("\(title) · \(fmtBytes(row.sizeBytes))").font(.subheadline)
                Text(row.state).font(.caption2).foregroundColor(.secondary)
            }
            Spacer()
            if let onPrimary, let primaryLabel, row.state != "expired" {
                Button(primaryLabel, action: onPrimary).buttonStyle(.borderedProminent).disabled(busy)
            }
            Button(role: .destructive, action: onDelete) {
                Image(systemName: "trash").foregroundColor(.secondary)
            }.disabled(busy)
        }
        .padding(.vertical, 4)
    }

    private func fmtBytes(_ n: Int64) -> String {
        let d = Double(n)
        if d >= 1e9 { return String(format: "%.2f GB", d / 1e9) }
        if d >= 1e6 { return String(format: "%.1f MB", d / 1e6) }
        if d >= 1e3 { return String(format: "%.0f KB", d / 1e3) }
        return "\(n) B"
    }
}

/// Identifiable wrapper so a temp file URL can drive a `.sheet(item:)`.
private struct ShareItem: Identifiable {
    let url: URL
    var id: String { url.path }
}

/// A UIKit share sheet (`UIActivityViewController`) for saving a received file to Files/Photos/etc.
private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
