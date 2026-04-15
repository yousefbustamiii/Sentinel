import Foundation
import Security

/// A strictly typed wrapper around macOS Keychain Services
public final class KeychainWrapper {
    
    public static let shared = KeychainWrapper()
    private init() {}

    private var baseAttributes: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
    }
    
    /// Saves or updates a string value for the given key securely
    public func save(password: String, service: String, account: String) -> Bool {
        guard let data = password.data(using: .utf8) else { return false }
        
        var query = baseAttributes
        query.merge([
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]) { _, new in new }
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        
        if status == errSecSuccess {
            let attributesToUpdate: [String: Any] = [
                kSecValueData as String: data,
                kSecAttrLabel as String: "Sentinel Administrative Password",
                kSecAttrDescription as String: "Local administrative credential for Sentinel security controls",
                kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            ]
            let updateStatus = SecItemUpdate(query as CFDictionary, attributesToUpdate as CFDictionary)
            return updateStatus == errSecSuccess
        } else if status == errSecItemNotFound {
            var newItem = query
            newItem[kSecValueData as String] = data
            newItem[kSecAttrLabel as String] = "Sentinel Administrative Password"
            newItem[kSecAttrDescription as String] = "Local administrative credential for Sentinel security controls"
            let addStatus = SecItemAdd(newItem as CFDictionary, nil)
            return addStatus == errSecSuccess
        }
        return false
    }
    
    /// Reads a saved string from the keychain
    public func read(service: String, account: String) -> String? {
        var query = baseAttributes
        query.merge([
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]) { _, new in new }
        
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        guard status == errSecSuccess, let data = dataTypeRef as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }
    
    /// Deletes a key from the keychain
    public func delete(service: String, account: String) -> Bool {
        var query = baseAttributes
        query.merge([
            kSecAttrService as String: service,
            kSecAttrAccount as String: account
        ]) { _, new in new }
        let status = SecItemDelete(query as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }
}
