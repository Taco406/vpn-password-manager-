// Codable mirrors of the Rust vault model (crates/core/src/vault/model.rs). Field names and JSON
// shapes must match serde's output exactly — item ids are LOWERCASE hyphenated UUID strings, the
// item type tag is `"type"`, and optional fields are omitted (not null) when absent.

import Foundation

/// The decrypted sync document: base64 item envelopes (each is ciphertext) + deletion tombstones.
struct VaultDocument: Codable {
    var format: UInt8
    var items: [String]
    /// (item_id, deleted_at) pairs — serde encodes tuples as 2-element JSON arrays.
    var tombstones: [[TombstoneField]]

    enum TombstoneField: Codable {
        case id(String)
        case ts(Int64)
        init(from decoder: Decoder) throws {
            let c = try decoder.singleValueContainer()
            if let s = try? c.decode(String.self) { self = .id(s) } else { self = .ts(try c.decode(Int64.self)) }
        }
        func encode(to encoder: Encoder) throws {
            var c = encoder.singleValueContainer()
            switch self {
            case .id(let s): try c.encode(s)
            case .ts(let t): try c.encode(t)
            }
        }
    }
}

struct VaultLogin: Codable {
    var username: String?
    var password: String?
    var totp: String?
}

struct VaultUrlMatch: Codable {
    var url: String
    var mode: String // "domain" | "host"
}

struct VaultCustomField: Codable {
    var name: String
    var value: String
    var secret: Bool
}

/// A vault item's plaintext. Card/identity/passkey ride through as raw JSON so an edit on the
/// phone can never drop fields it doesn't model.
struct VaultItem: Codable, Identifiable {
    var id: String // lowercase hyphenated uuid
    var type: String // "login" | "note" | "card" | "identity" | "passkey"
    var title: String
    var tags: [String]
    var urls: [VaultUrlMatch]
    var notes: String?
    var customFields: [VaultCustomField]
    var login: VaultLogin?
    var card: RawJSON?
    var identity: RawJSON?
    var passkey: RawJSON?
    var createdAt: Int64
    var updatedAt: Int64
    var passwordChangedAt: Int64?

    enum CodingKeys: String, CodingKey {
        case id, type, title, tags, urls, notes
        case customFields = "custom_fields"
        case login, card, identity, passkey
        case createdAt = "created_at"
        case updatedAt = "updated_at"
        case passwordChangedAt = "password_changed_at"
    }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(String.self, forKey: .id)
        type = try c.decode(String.self, forKey: .type)
        title = try c.decode(String.self, forKey: .title)
        tags = try c.decodeIfPresent([String].self, forKey: .tags) ?? []
        urls = try c.decodeIfPresent([VaultUrlMatch].self, forKey: .urls) ?? []
        notes = try c.decodeIfPresent(String.self, forKey: .notes)
        customFields = try c.decodeIfPresent([VaultCustomField].self, forKey: .customFields) ?? []
        login = try c.decodeIfPresent(VaultLogin.self, forKey: .login)
        card = try c.decodeIfPresent(RawJSON.self, forKey: .card)
        identity = try c.decodeIfPresent(RawJSON.self, forKey: .identity)
        passkey = try c.decodeIfPresent(RawJSON.self, forKey: .passkey)
        createdAt = try c.decode(Int64.self, forKey: .createdAt)
        updatedAt = try c.decode(Int64.self, forKey: .updatedAt)
        passwordChangedAt = try c.decodeIfPresent(Int64.self, forKey: .passwordChangedAt)
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(type, forKey: .type)
        try c.encode(title, forKey: .title)
        try c.encode(tags, forKey: .tags)
        try c.encode(urls, forKey: .urls)
        try c.encodeIfPresent(notes, forKey: .notes)
        try c.encode(customFields, forKey: .customFields)
        try c.encodeIfPresent(login, forKey: .login)
        try c.encodeIfPresent(card, forKey: .card)
        try c.encodeIfPresent(identity, forKey: .identity)
        try c.encodeIfPresent(passkey, forKey: .passkey)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encode(updatedAt, forKey: .updatedAt)
        try c.encodeIfPresent(passwordChangedAt, forKey: .passwordChangedAt)
    }

    /// A fresh login item (mirrors Item::new_login).
    static func newLogin(title: String, now: Int64) -> VaultItem {
        var it = VaultItem.empty
        it.id = UUID().uuidString.lowercased()
        it.type = "login"
        it.title = title
        it.login = VaultLogin()
        it.createdAt = now
        it.updatedAt = now
        it.passwordChangedAt = now
        return it
    }

    private static var empty: VaultItem {
        // Round-trip through JSON to use the tolerant decoder for construction.
        let json = #"{"id":"00000000-0000-0000-0000-000000000000","type":"login","title":"","created_at":0,"updated_at":0}"#
        // swiftlint:disable:next force_try
        return try! JSONDecoder().decode(VaultItem.self, from: Data(json.utf8))
    }
}

/// Passes unknown JSON through encode/decode untouched (order-insensitive, structure-preserving).
struct RawJSON: Codable {
    let value: Any

    init(from decoder: Decoder) throws {
        let c = try decoder.singleValueContainer()
        if let v = try? c.decode(Bool.self) { value = v }
        else if let v = try? c.decode(Int64.self) { value = v }
        else if let v = try? c.decode(Double.self) { value = v }
        else if let v = try? c.decode(String.self) { value = v }
        else if let v = try? c.decode([RawJSON].self) { value = v }
        else if let v = try? c.decode([String: RawJSON].self) { value = v }
        else if c.decodeNil() { value = NSNull() }
        else { throw DecodingError.dataCorruptedError(in: c, debugDescription: "unsupported JSON") }
    }

    func encode(to encoder: Encoder) throws {
        var c = encoder.singleValueContainer()
        switch value {
        case let v as Bool: try c.encode(v)
        case let v as Int64: try c.encode(v)
        case let v as Double: try c.encode(v)
        case let v as String: try c.encode(v)
        case let v as [RawJSON]: try c.encode(v)
        case let v as [String: RawJSON]: try c.encode(v)
        default: try c.encodeNil()
        }
    }
}
