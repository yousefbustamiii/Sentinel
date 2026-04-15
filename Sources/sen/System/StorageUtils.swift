import Foundation

/// Centralized utilities for directory management and JSON serialization.
internal struct StorageUtils {
    
    /// Shared JSON encoder configured for forensic durability.
    static let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return encoder
    }()
    
    /// Shared JSON decoder.
    static let decoder = JSONDecoder()
    
    /// Ensures the parent directory for a given file URL exists.
    static func ensureDirectoryExists(for fileURL: URL) {
        let directory = fileURL.deletingLastPathComponent()
        if !FileManager.default.fileExists(atPath: directory.path) {
            try? FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        }
    }

    static func writeAtomically(_ data: Data, to url: URL, permissions: Int = 0o600) throws {
        ensureDirectoryExists(for: url)
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: url.path)
    }
}
