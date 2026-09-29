import Foundation
import Security

/// Per-application Keychain storage with device-only, unlocked accessibility.
struct KeychainSecureStore: SnaplinkSecureStore {
    private let service: String

    init(service: String = "com.snaplink.sso") {
        self.service = service
    }

    func read(account: String) throws -> Data? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else {
            throw keychainError("read", status: status)
        }
        guard data.count <= Self.maximumValueBytes else {
            throw SnaplinkAuthError(code: "secure_storage_error", message: "Keychain value exceeds the SDK storage limit")
        }
        return data
    }

    func write(_ data: Data, account: String) throws {
        guard data.count <= Self.maximumValueBytes else {
            throw SnaplinkAuthError(code: "secure_storage_error", message: "Keychain value exceeds the SDK storage limit")
        }
        var query = baseQuery(account: account)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if status == errSecSuccess { return }
        guard status == errSecItemNotFound else { throw keychainError("update", status: status) }
        query.merge(attributes) { _, new in new }
        let addStatus = SecItemAdd(query as CFDictionary, nil)
        if addStatus == errSecSuccess { return }
        if addStatus == errSecDuplicateItem {
            let retryStatus = SecItemUpdate(baseQuery(account: account) as CFDictionary, attributes as CFDictionary)
            if retryStatus == errSecSuccess { return }
            throw keychainError("update", status: retryStatus)
        }
        throw keychainError("add", status: addStatus)
    }

    func delete(account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw keychainError("delete", status: status)
        }
    }

    private func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]
    }

    private func keychainError(_ operation: String, status: OSStatus) -> SnaplinkAuthError {
        SnaplinkAuthError(
            code: "secure_storage_error",
            message: "Keychain \(operation) failed (status \(status))"
        )
    }

    private static let maximumValueBytes = 64 * 1024
}
