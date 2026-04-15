import Foundation

enum FindingStorePersistence {
    static func persist(_ findings: [String: FindingRecord]) throws {
        try write(findings, to: FindingStorePath.backupURL)
        try write(findings, to: FindingStorePath.url)
    }

    static func write(_ findings: [String: FindingRecord], to url: URL) throws {
        let data = try StorageUtils.encoder.encode(findings)
        StorageUtils.ensureDirectoryExists(for: url)
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
