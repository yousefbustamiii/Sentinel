import Foundation
import CryptoSwift
import Security

/// Standardizes cryptographic key derivation for Sentinel administrative authentication.
/// Algorithm: Scrypt (N=16384, r=8, p=1, 32-byte salt, 64-byte key).
internal struct PasswordHasher {
    struct StoredHash {
        let algorithm: String
        let cost: Int
        let blockSize: Int
        let parallelization: Int
        let salt: Data
        let derivedKey: Data
    }

    private static let cost:       Int = 16384 // N (Cost factor)
    private static let blockSize:  Int = 8     // r (Block size)
    private static let parallel:   Int = 1     // p (Parallelization)
    private static let saltLength: Int = 32
    private static let keyLength:  Int = 64
    private static let algorithm = "scrypt"

    /// Derives a salted key from the provided plain text password using Scrypt.
    /// Returns a versioned storable string in the format "scrypt:N=...:r=...:p=...:<salt>:<derivedKey>".
    static func hash(_ plain: String) -> String? {
        guard let passwordData = plain.data(using: .utf8) else { return nil }

        var salt = Data(count: saltLength)
        let saltResult = salt.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, saltLength, $0.baseAddress!)
        }
        guard saltResult == errSecSuccess else { return nil }

        do {
            let scrypt = try Scrypt(
                password: Array(passwordData),
                salt: Array(salt),
                dkLen: keyLength,
                N: cost,
                r: blockSize,
                p: parallel
            )
            let bytes = try scrypt.calculate()
            let derivedKey = Data(bytes)
            return [
                algorithm,
                "N=\(cost)",
                "r=\(blockSize)",
                "p=\(parallel)",
                salt.base64EncodedString(),
                derivedKey.base64EncodedString()
            ].joined(separator: ":")
        } catch {
            return nil
        }
    }

    static func parseStoredHash(_ stored: String) -> StoredHash? {
        let parts = stored.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 6, parts[0] == algorithm else { return nil }
        guard
            let cost = parseParameter(parts[1], name: "N"),
            let blockSize = parseParameter(parts[2], name: "r"),
            let parallelization = parseParameter(parts[3], name: "p"),
            let salt = Data(base64Encoded: parts[4]),
            let derivedKey = Data(base64Encoded: parts[5]),
            salt.count == saltLength,
            derivedKey.count == keyLength
        else {
            return nil
        }

        return StoredHash(
            algorithm: parts[0],
            cost: cost,
            blockSize: blockSize,
            parallelization: parallelization,
            salt: salt,
            derivedKey: derivedKey
        )
    }

    static func isValidStoredRepresentation(_ stored: String) -> Bool {
        parseStoredHash(stored) != nil
    }

    static func verify(_ plain: String, against stored: String) -> Bool {
        guard
            let storedHash = parseStoredHash(stored),
            let passwordData = plain.data(using: .utf8)
        else {
            return false
        }

        do {
            let scrypt = try Scrypt(
                password: Array(passwordData),
                salt: Array(storedHash.salt),
                dkLen: storedHash.derivedKey.count,
                N: storedHash.cost,
                r: storedHash.blockSize,
                p: storedHash.parallelization
            )
            let bytes = try scrypt.calculate()
            let candidateKey = Data(bytes)

            return constantTimeEquals(candidateKey, storedHash.derivedKey)
        } catch {
            return false
        }
    }

    private static func parseParameter(_ parameter: String, name: String) -> Int? {
        let components = parameter.split(separator: "=", maxSplits: 1).map(String.init)
        guard components.count == 2, components[0] == name, let value = Int(components[1]), value > 0 else {
            return nil
        }
        return value
    }

    private static func constantTimeEquals(_ lhs: Data, _ rhs: Data) -> Bool {
        guard lhs.count == rhs.count else { return false }
        return lhs.withUnsafeBytes { lhsBytes in
            rhs.withUnsafeBytes { rhsBytes in
                guard let lhsBase = lhsBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                      let rhsBase = rhsBytes.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return false
                }

                var difference: UInt8 = 0
                for index in 0..<lhs.count {
                    difference |= lhsBase[index] ^ rhsBase[index]
                }
                return difference == 0
            }
        }
    }
}
