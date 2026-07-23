// The vault UI: master-password unlock (with optional Face ID), the item list, item detail
// (copy username/password, live TOTP codes), and add/edit for logins and notes. Same dark
// Card aesthetic as the rest of the app; same vault semantics as the desktop.

import SwiftUI
import UIKit
import UniformTypeIdentifiers

// MARK: - Clipboard (sensitive values expire and stay off Handoff/Universal Clipboard)

enum Clipboard {
    static func copy(_ value: String, sensitive: Bool = false) {
        if sensitive {
            UIPasteboard.general.setItems(
                [[UTType.utf8PlainText.identifier: value]],
                options: [
                    .localOnly: true,
                    .expirationDate: Date().addingTimeInterval(60),
                ])
        } else {
            UIPasteboard.general.string = value
        }
    }
}

// MARK: - Unlock

struct UnlockView: View {
    @ObservedObject var vault: VaultStore
    let onForgetServer: () -> Void
    @State private var password = ""
    @State private var confirmForget = false

    var body: some View {
        VStack(spacing: 16) {
            Card {
                VStack(alignment: .leading, spacing: 12) {
                    Text("Unlock your vault").font(.subheadline.bold())
                    Text("Enter the same master password you use on your computer. It never leaves this phone — it unwraps your vault key locally.")
                        .font(.caption).foregroundColor(.gray)

                    SecureField("Master password", text: $password)
                        .textFieldStyle(.roundedBorder)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .onSubmit(unlock)

                    if let error = vault.error {
                        Text(error).font(.caption).foregroundColor(Color(hex: 0xF87171))
                    }

                    Button(vault.busy ? "Unlocking…" : "Unlock") { unlock() }
                        .buttonStyle(.borderedProminent)
                        .disabled(vault.busy || password.isEmpty)

                    if VaultStore.faceIDAvailable() {
                        Button {
                            Task { await vault.unlockWithFaceID() }
                        } label: {
                            Label("Unlock with Face ID", systemImage: "faceid")
                        }
                        .buttonStyle(.bordered)
                        .disabled(vault.busy)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
            }

            Button("Connect to a different server") { confirmForget = true }
                .font(.caption)
                .foregroundColor(.gray)
                .confirmationDialog(
                    "Forget this sync server? Your passwords stay safe on the server and your other devices — this only disconnects this phone.",
                    isPresented: $confirmForget, titleVisibility: .visible
                ) {
                    Button("Forget server", role: .destructive) { onForgetServer() }
                }
        }
    }

    private func unlock() {
        guard !password.isEmpty, !vault.busy else { return }
        let entered = password
        Task {
            await vault.unlock(masterPassword: entered)
            if vault.isUnlocked { password = "" }
        }
    }
}

// MARK: - Item list

struct VaultListView: View {
    @ObservedObject var vault: VaultStore
    @State private var search = ""
    @State private var adding = false
    @State private var faceIDOn = VaultStore.faceIDAvailable()
    /// Drives the NavigationSplitView: side-by-side list/detail on iPad, and a push on iPhone
    /// (the split view collapses to a stack automatically on a compact width class).
    @State private var selectedId: String?

    private var filtered: [VaultItem] {
        let q = search.trimmingCharacters(in: .whitespaces).lowercased()
        guard !q.isEmpty else { return vault.items }
        return vault.items.filter {
            $0.title.lowercased().contains(q)
                || ($0.login?.username ?? "").lowercased().contains(q)
                || $0.urls.contains { $0.url.lowercased().contains(q) }
        }
    }
    private var logins: [VaultItem] { filtered.filter { $0.type == "login" } }
    private var others: [VaultItem] { filtered.filter { $0.type != "login" } }

    var body: some View {
        NavigationSplitView {
            List(selection: $selectedId) {
                if vault.offline {
                    Label(
                        "Offline — showing your vault from the last sync. Changes are off until the server is reachable; pull down to retry.",
                        systemImage: "wifi.slash")
                        .font(.caption).foregroundColor(Color(hex: 0xFBBF24))
                        .listRowBackground(Color(hex: 0x0F141C))
                }
                if let error = vault.error {
                    Text(error)
                        .font(.caption).foregroundColor(Color(hex: 0xF87171))
                        .listRowBackground(Color(hex: 0x0F141C))
                }
                if vault.items.isEmpty && !vault.busy {
                    Text("No items yet. Tap + to add your first password — it syncs to all your devices.")
                        .font(.caption).foregroundColor(.gray)
                        .listRowBackground(Color(hex: 0x0F141C))
                }
                if !logins.isEmpty {
                    Section("Logins") {
                        ForEach(logins) { item in row(item) }
                    }
                }
                if !others.isEmpty {
                    Section("Other items") {
                        ForEach(others) { item in row(item) }
                    }
                }
            }
            .scrollContentBackground(.hidden)
            .background(Color(hex: 0x0A0E14))
            .searchable(text: $search, prompt: "Search vault")
            .refreshable { try? await vault.pull() }
            .navigationTitle("Vault")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Menu {
                        Button {
                            if faceIDOn {
                                vault.disableFaceID()
                            } else {
                                vault.enableFaceID()
                            }
                            faceIDOn.toggle()
                        } label: {
                            Label(
                                faceIDOn ? "Turn off Face ID unlock" : "Unlock with Face ID next time",
                                systemImage: "faceid")
                        }
                        Button {
                            Task { try? await vault.pull() }
                        } label: {
                            Label("Sync now", systemImage: "arrow.triangle.2.circlepath")
                        }
                        Button(role: .destructive) {
                            vault.lock()
                        } label: {
                            Label("Lock vault", systemImage: "lock.fill")
                        }
                    } label: {
                        Image(systemName: "ellipsis.circle")
                    }
                }
                ToolbarItem(placement: .navigationBarTrailing) {
                    HStack(spacing: 12) {
                        if vault.busy { ProgressView() }
                        Button { adding = true } label: { Image(systemName: "plus") }
                    }
                }
            }
            .sheet(isPresented: $adding) {
                NavigationStack { ItemEditView(vault: vault) }
                    .preferredColorScheme(.dark)
            }
        } detail: {
            if let id = selectedId {
                NavigationStack { ItemDetailView(vault: vault, itemId: id) }
            } else {
                ZStack {
                    Color(hex: 0x0A0E14).ignoresSafeArea()
                    VStack(spacing: 8) {
                        Image(systemName: "key.fill")
                            .font(.largeTitle)
                            .foregroundColor(.gray.opacity(0.4))
                        Text("Select an item").foregroundColor(.gray)
                    }
                }
            }
        }
        .navigationSplitViewStyle(.balanced)
    }

    private func row(_ item: VaultItem) -> some View {
        HStack(spacing: 12) {
            Image(systemName: Self.icon(for: item.type))
                .foregroundColor(Color(hex: 0x22D3EE))
                .frame(width: 24)
            VStack(alignment: .leading, spacing: 2) {
                Text(item.title.isEmpty ? "Untitled" : item.title)
                    .font(.subheadline)
                if let u = item.login?.username, !u.isEmpty {
                    Text(u).font(.caption).foregroundColor(.gray)
                } else if item.type != "login" {
                    Text(item.type.capitalized).font(.caption).foregroundColor(.gray)
                }
            }
        }
        .tag(item.id)
        .listRowBackground(Color(hex: 0x0F141C))
    }

    static func icon(for type: String) -> String {
        switch type {
        case "login": return "key.fill"
        case "note": return "note.text"
        case "card": return "creditcard"
        case "identity": return "person.text.rectangle"
        case "passkey": return "person.badge.key"
        default: return "questionmark.circle"
        }
    }
}

// MARK: - Item detail

struct ItemDetailView: View {
    @ObservedObject var vault: VaultStore
    let itemId: String
    @Environment(\.dismiss) private var dismiss
    @State private var showPassword = false
    @State private var editing = false
    @State private var confirmDelete = false
    @State private var copied: String?

    private var item: VaultItem? { vault.items.first { $0.id == itemId } }

    var body: some View {
        List {
            if let item {
                if let login = item.login {
                    Section("Login") {
                        if let u = login.username, !u.isEmpty {
                            copyRow(label: "Username", value: u, sensitive: false)
                        }
                        if let p = login.password, !p.isEmpty {
                            passwordRow(p)
                        }
                        if let t = login.totp, let entry = TotpParse.entry(from: t, title: item.title) {
                            totpRow(entry)
                        }
                    }
                }
                if !item.urls.isEmpty {
                    Section("Websites") {
                        ForEach(item.urls.indices, id: \.self) { i in
                            copyRow(label: item.urls[i].url, value: item.urls[i].url, sensitive: false, labelOnly: true)
                        }
                    }
                }
                if let notes = item.notes, !notes.isEmpty {
                    Section("Notes") {
                        Text(notes).font(.callout)
                            .listRowBackground(Color(hex: 0x0F141C))
                    }
                }
                if !item.customFields.isEmpty {
                    Section("Custom fields") {
                        ForEach(item.customFields.indices, id: \.self) { i in
                            let f = item.customFields[i]
                            copyRow(
                                label: f.name,
                                value: f.value,
                                sensitive: f.secret,
                                masked: f.secret)
                        }
                    }
                }
                if item.card != nil || item.identity != nil || item.passkey != nil {
                    Section {
                        Text("This item has \(item.type) details — view and edit them on your computer. Editing here keeps them intact.")
                            .font(.caption).foregroundColor(.gray)
                            .listRowBackground(Color(hex: 0x0F141C))
                    }
                }
                Section {
                    Button("Delete item", role: .destructive) { confirmDelete = true }
                        .listRowBackground(Color(hex: 0x0F141C))
                }
            } else {
                Text("This item is gone (deleted on another device).")
                    .font(.caption).foregroundColor(.gray)
                    .listRowBackground(Color(hex: 0x0F141C))
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color(hex: 0x0A0E14))
        .navigationTitle(item.map { $0.title.isEmpty ? "Untitled" : $0.title } ?? "Item")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            if let item, item.type == "login" || item.type == "note" {
                ToolbarItem(placement: .navigationBarTrailing) {
                    Button("Edit") { editing = true }
                }
            }
        }
        .sheet(isPresented: $editing) {
            if let item {
                NavigationStack { ItemEditView(vault: vault, item: item) }
                    .preferredColorScheme(.dark)
            }
        }
        .confirmationDialog(
            "Delete this item on all your devices?",
            isPresented: $confirmDelete, titleVisibility: .visible
        ) {
            Button("Delete", role: .destructive) {
                guard let item else { return }
                Task {
                    await vault.delete(item)
                    if vault.error == nil { dismiss() }
                }
            }
        }
    }

    private func copyRow(
        label: String, value: String, sensitive: Bool, masked: Bool = false, labelOnly: Bool = false
    ) -> some View {
        Button {
            Clipboard.copy(value, sensitive: sensitive)
            flashCopied(label)
        } label: {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text(label).font(labelOnly ? .callout : .caption)
                        .foregroundColor(labelOnly ? .white : .gray)
                    if !labelOnly {
                        Text(masked ? "••••••••" : value)
                            .font(.callout)
                            .foregroundColor(.white)
                            .lineLimit(1)
                    }
                }
                Spacer()
                Image(systemName: copied == label ? "checkmark" : "doc.on.doc")
                    .font(.caption)
                    .foregroundColor(copied == label ? Color(hex: 0x2ED47A) : .gray)
            }
        }
        .listRowBackground(Color(hex: 0x0F141C))
    }

    private func passwordRow(_ password: String) -> some View {
        HStack {
            VStack(alignment: .leading, spacing: 2) {
                Text("Password").font(.caption).foregroundColor(.gray)
                Text(showPassword ? password : "••••••••")
                    .font(.system(.callout, design: .monospaced))
                    .lineLimit(1)
            }
            Spacer()
            Button {
                showPassword.toggle()
            } label: {
                Image(systemName: showPassword ? "eye.slash" : "eye")
                    .font(.caption).foregroundColor(.gray)
            }
            .buttonStyle(.plain)
            Button {
                Clipboard.copy(password, sensitive: true)
                flashCopied("Password")
            } label: {
                Image(systemName: copied == "Password" ? "checkmark" : "doc.on.doc")
                    .font(.caption)
                    .foregroundColor(copied == "Password" ? Color(hex: 0x2ED47A) : .gray)
            }
            .buttonStyle(.plain)
        }
        .listRowBackground(Color(hex: 0x0F141C))
    }

    private func totpRow(_ entry: TotpEntry) -> some View {
        TimelineView(.periodic(from: .now, by: 1)) { context in
            let code = Rfc6238.code(
                secret: entry.secret, algo: entry.algo, digits: entry.digits,
                period: entry.period, at: context.date)
            let remaining = Rfc6238.remainingSeconds(period: entry.period, at: context.date)
            Button {
                Clipboard.copy(code, sensitive: true)
                flashCopied("One-time code")
            } label: {
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("One-time code").font(.caption).foregroundColor(.gray)
                        Text(code)
                            .font(.system(.title3, design: .monospaced).bold())
                            .foregroundColor(Color(hex: 0x22D3EE))
                    }
                    Spacer()
                    Text("\(remaining)s")
                        .font(.caption.monospacedDigit())
                        .foregroundColor(remaining <= 5 ? Color(hex: 0xF87171) : .gray)
                }
            }
        }
        .listRowBackground(Color(hex: 0x0F141C))
    }

    private func flashCopied(_ label: String) {
        copied = label
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
            if copied == label { copied = nil }
        }
    }
}

// MARK: - Add / edit

struct ItemEditView: View {
    @ObservedObject var vault: VaultStore
    @Environment(\.dismiss) private var dismiss

    private let original: VaultItem?
    @State private var kind: String
    @State private var title: String
    @State private var username: String
    @State private var password: String
    @State private var showPassword = false
    @State private var website: String
    @State private var totp: String
    @State private var notes: String
    @State private var saving = false

    init(vault: VaultStore, item: VaultItem? = nil) {
        _vault = ObservedObject(wrappedValue: vault)
        original = item
        _kind = State(initialValue: item?.type ?? "login")
        _title = State(initialValue: item?.title ?? "")
        _username = State(initialValue: item?.login?.username ?? "")
        _password = State(initialValue: item?.login?.password ?? "")
        _website = State(initialValue: item?.urls.first?.url ?? "")
        _totp = State(initialValue: item?.login?.totp ?? "")
        _notes = State(initialValue: item?.notes ?? "")
    }

    var body: some View {
        Form {
            if original == nil {
                Section {
                    Picker("Type", selection: $kind) {
                        Text("Login").tag("login")
                        Text("Secure note").tag("note")
                    }
                    .pickerStyle(.segmented)
                    .listRowBackground(Color(hex: 0x0F141C))
                }
            }
            Section {
                TextField("Title", text: $title)
                    .listRowBackground(Color(hex: 0x0F141C))
            }
            if kind == "login" {
                Section("Login") {
                    TextField("Username or email", text: $username)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.emailAddress)
                        .listRowBackground(Color(hex: 0x0F141C))
                    HStack {
                        Group {
                            if showPassword {
                                TextField("Password", text: $password)
                                    .font(.system(.body, design: .monospaced))
                            } else {
                                SecureField("Password", text: $password)
                            }
                        }
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        Button {
                            showPassword.toggle()
                        } label: {
                            Image(systemName: showPassword ? "eye.slash" : "eye")
                                .foregroundColor(.gray)
                        }
                        .buttonStyle(.plain)
                        Button {
                            password = Self.generatePassword()
                            showPassword = true
                        } label: {
                            Image(systemName: "die.face.5")
                                .foregroundColor(Color(hex: 0x22D3EE))
                        }
                        .buttonStyle(.plain)
                    }
                    .listRowBackground(Color(hex: 0x0F141C))
                    TextField("Website (example.com)", text: $website)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .keyboardType(.URL)
                        .listRowBackground(Color(hex: 0x0F141C))
                    TextField("One-time code secret (optional)", text: $totp)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                        .font(.system(.body, design: .monospaced))
                        .listRowBackground(Color(hex: 0x0F141C))
                }
            }
            Section("Notes") {
                TextEditor(text: $notes)
                    .frame(minHeight: 80)
                    .listRowBackground(Color(hex: 0x0F141C))
            }
            if let error = vault.error {
                Section {
                    Text(error).font(.caption).foregroundColor(Color(hex: 0xF87171))
                        .listRowBackground(Color(hex: 0x0F141C))
                }
            }
        }
        .scrollContentBackground(.hidden)
        .background(Color(hex: 0x0A0E14))
        .navigationTitle(original == nil ? "New item" : "Edit item")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .cancellationAction) {
                Button("Cancel") { dismiss() }
            }
            ToolbarItem(placement: .confirmationAction) {
                Button(saving ? "Saving…" : "Save") { save() }
                    .disabled(saving || title.trimmingCharacters(in: .whitespaces).isEmpty)
            }
        }
    }

    private func save() {
        saving = true
        let now = Int64(Date().timeIntervalSince1970)
        var item = original ?? VaultItem.newLogin(title: "", now: now)
        if original == nil {
            item.type = kind
            if kind != "login" { item.login = nil; item.passwordChangedAt = nil }
        }
        item.title = title.trimmingCharacters(in: .whitespaces)
        if item.type == "login" {
            var login = item.login ?? VaultLogin()
            let oldPassword = login.password
            login.username = username.isEmpty ? nil : username
            login.password = password.isEmpty ? nil : password
            login.totp = totp.trimmingCharacters(in: .whitespaces).isEmpty ? nil : totp
            item.login = login
            if oldPassword != login.password { item.passwordChangedAt = now }
            let site = website.trimmingCharacters(in: .whitespaces)
            if site.isEmpty {
                if !item.urls.isEmpty { item.urls.removeFirst() }
            } else if item.urls.isEmpty {
                item.urls = [VaultUrlMatch(url: site, mode: "domain")]
            } else {
                item.urls[0] = VaultUrlMatch(url: site, mode: item.urls[0].mode)
            }
        }
        item.notes = notes.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : notes
        Task {
            await vault.save(item)
            saving = false
            if vault.error == nil { dismiss() }
        }
    }

    static func generatePassword() -> String {
        // No ambiguous characters (0/O, 1/l/I) — these get typed by hand on other screens.
        let chars = Array("abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*-_=+")
        return String((0..<20).compactMap { _ in chars.randomElement() })
    }
}

// MARK: - TOTP parsing (otpauth:// URI or bare base32, same as the Rust core's totp module)

enum TotpParse {
    static func entry(from raw: String, title: String) -> TotpEntry? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if trimmed.lowercased().hasPrefix("otpauth://") {
            guard let comps = URLComponents(string: trimmed) else { return nil }
            var secret: Data?
            var algo = TotpAlgo.sha1
            var digits = 6
            var period = 30
            for q in comps.queryItems ?? [] {
                switch q.name.lowercased() {
                case "secret": secret = base32Decode(q.value ?? "")
                case "algorithm":
                    switch (q.value ?? "").uppercased() {
                    case "SHA256": algo = .sha256
                    case "SHA512": algo = .sha512
                    default: algo = .sha1
                    }
                case "digits": digits = Int(q.value ?? "") ?? 6
                case "period": period = Int(q.value ?? "") ?? 30
                default: break
                }
            }
            guard let s = secret, !s.isEmpty, (6...8).contains(digits), period > 0 else { return nil }
            return TotpEntry(title: title, secret: s, algo: algo, digits: digits, period: period)
        }
        guard let s = base32Decode(trimmed), !s.isEmpty else { return nil }
        return TotpEntry(title: title, secret: s, algo: .sha1, digits: 6, period: 30)
    }

    /// RFC 4648 base32 (case-insensitive, padding and spaces ignored).
    static func base32Decode(_ s: String) -> Data? {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
        var index = [Character: Int]()
        for (i, c) in alphabet.enumerated() { index[c] = i }
        var bits = 0
        var value = 0
        var out = Data()
        for ch in s.uppercased() where ch != "=" && ch != " " {
            guard let v = index[ch] else { return nil }
            value = (value << 5) | v
            bits += 5
            if bits >= 8 {
                out.append(UInt8((value >> (bits - 8)) & 0xff))
                bits -= 8
            }
        }
        return out
    }
}
