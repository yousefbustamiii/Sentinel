import Foundation

/// Manages administrative authentication via the macOS Keychain.
public struct AuthenticationService {

    /// Checks if a valid versioned administrative password representation has been configured.
    public static func isPasswordSet() -> Bool {
        guard let stored = KeychainWrapper.shared.read(
            service: Configuration.shared.keychainService,
            account: Configuration.shared.keychainAccount
        ) else { return false }
        return isStoredPasswordValid(stored)
    }

    /// Sets or updates the administrative password.
    public static func setup(_ plain: String) -> Bool {
        guard let stored = PasswordHasher.hash(plain) else { return false }
        return KeychainWrapper.shared.save(
            password: stored,
            service: Configuration.shared.keychainService,
            account: Configuration.shared.keychainAccount
        )
    }

    /// Verifies the provided password against the secure hardware store.
    public static func verifyPassword(_ plain: String) -> Bool {
        guard let stored = KeychainWrapper.shared.read(
            service: Configuration.shared.keychainService,
            account: Configuration.shared.keychainAccount
        ) else { return false }
        return PasswordHasher.verify(plain, against: stored)
    }

    /// Removes the administrative password from the system.
    public static func removePassword() {
        _ = KeychainWrapper.shared.delete(
            service: Configuration.shared.keychainService,
            account: Configuration.shared.keychainAccount
        )
    }

    static func isStoredPasswordValid(_ stored: String?) -> Bool {
        guard let stored else { return false }
        return PasswordHasher.isValidStoredRepresentation(stored)
    }
}
