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
    /// Decrypted file(s) waiting to be saved/shared (temp URLs for the share sheet). A single-file
    /// transfer yields one URL; a received bundle yields several.
    @Published var shareItems: [URL] = []

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

    func send(
        fileURL: URL, recipientDeviceId: String?, retention: ApiClient.Retention, vaultKey: Data
    ) async {
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
                recipientDeviceId: recipientDeviceId, sizeBytes: bytes.count, ciphertext: blob,
                retention: retention)
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
            if meta.mime == VaultCrypto.bundleMime {
                // A multi-file bundle: unpack and write each file into a temp folder, then share them
                // all so the user can save the set at once.
                let entries = try VaultCrypto.unpackBundle(bytes)
                let dir = FileManager.default.temporaryDirectory
                    .appendingPathComponent("bundle-\(UUID().uuidString)", isDirectory: true)
                try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
                var urls: [URL] = []
                for e in entries {
                    let leaf = (e.name as NSString).lastPathComponent
                    let url = dir.appendingPathComponent(leaf.isEmpty ? "file" : leaf)
                    try e.data.write(to: url, options: .atomic)
                    urls.append(url)
                }
                shareItems = urls
                status = "\(entries.count) files ready to save."
            } else {
                let safeName = (meta.filename as NSString).lastPathComponent
                let url = FileManager.default.temporaryDirectory
                    .appendingPathComponent(safeName.isEmpty ? "download.bin" : safeName)
                try bytes.write(to: url, options: .atomic)
                shareItems = [url]
                status = nil
            }
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

/// How a sent file is kept on the relay. Maps to `ApiClient.Retention`.
private enum RetentionMode: String, CaseIterable, Identifiable {
    case days, onDownload, permanent
    var id: String { rawValue }
    var label: String {
        switch self {
        case .days: return "For a few days"
        case .onDownload: return "Until downloaded"
        case .permanent: return "Permanently"
        }
    }
}

struct TransfersView: View {
    @ObservedObject var vault: VaultStore
    @StateObject private var model = TransfersModel()
    @State private var picking = false
    @State private var recipient: String? // nil = all my devices
    @State private var retMode: RetentionMode = .days
    @State private var ttlDays = 1

    private var retention: ApiClient.Retention {
        switch retMode {
        case .permanent: return ApiClient.Retention(permanent: true)
        case .onDownload: return ApiClient.Retention(deleteOnDownload: true)
        case .days: return ApiClient.Retention(ttlDays: ttlDays)
        }
    }

    private var retentionBlurb: String {
        switch retMode {
        case .permanent:
            return "Kept on your server until you delete it — counts against your storage quota."
        case .onDownload:
            return "Deleted the moment one of your devices downloads it."
        case .days:
            return "Deleted automatically after \(ttlDays) day\(ttlDays == 1 ? "" : "s"), downloaded or not."
        }
    }

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
                let ret = retention
                Task {
                    await model.send(
                        fileURL: url, recipientDeviceId: recipient, retention: ret, vaultKey: key)
                }
            }
            .sheet(isPresented: Binding(get: { !model.shareItems.isEmpty },
                                        set: { if !$0 { model.shareItems = [] } })) {
                ShareSheet(items: model.shareItems)
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
                Picker("Keep", selection: $retMode) {
                    ForEach(RetentionMode.allCases) { m in Text(m.label).tag(m) }
                }
                .pickerStyle(.menu)
                if retMode == .days {
                    Stepper("Delete after \(ttlDays) day\(ttlDays == 1 ? "" : "s")",
                            value: $ttlDays, in: 1...365)
                        .font(.subheadline)
                }
                Text(retentionBlurb).font(.caption2).foregroundColor(.secondary)
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
                Text(caption).font(.caption2).foregroundColor(.secondary)
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

    /// State + retention, e.g. "delivered", "pending · kept", "pending · deletes on download",
    /// or "pending · expires in 3d".
    private var caption: String {
        if row.state == "expired" { return "expired" }
        var parts = [row.state]
        if row.permanent == true {
            parts.append("kept")
        } else if row.deleteOnDownload == true {
            parts.append("deletes on download")
        } else if row.state == "pending", let exp = expiresIn(row.expiresAt) {
            parts.append(exp)
        }
        return parts.joined(separator: " · ")
    }

    private func expiresIn(_ unix: Int64) -> String? {
        guard unix > 0 else { return nil }
        let secs = unix - Int64(Date().timeIntervalSince1970)
        if secs <= 0 { return "expired" }
        let days = secs / 86400
        if days >= 1 { return "expires in \(days)d" }
        let hrs = secs / 3600
        if hrs >= 1 { return "expires in \(hrs)h" }
        return "expires in \(max(1, secs / 60)) min"
    }

    private func fmtBytes(_ n: Int64) -> String {
        let d = Double(n)
        if d >= 1e9 { return String(format: "%.2f GB", d / 1e9) }
        if d >= 1e6 { return String(format: "%.1f MB", d / 1e6) }
        if d >= 1e3 { return String(format: "%.0f KB", d / 1e3) }
        return "\(n) B"
    }
}

/// A UIKit share sheet (`UIActivityViewController`) for saving received file(s) to Files/Photos/etc.
private struct ShareSheet: UIViewControllerRepresentable {
    let items: [Any]
    func makeUIViewController(context: Context) -> UIActivityViewController {
        UIActivityViewController(activityItems: items, applicationActivities: nil)
    }
    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}
