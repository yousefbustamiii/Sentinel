import Foundation

enum TrustStorePersistence {
    static func write(_ entries: [TrustEntry], to url: URL) throws {
        let data = try StorageUtils.encoder.encode(entries)
        try StorageUtils.writeAtomically(data, to: url)
    }

    static func persist(_ entries: [TrustEntry]) throws {
        try write(entries, to: TrustStorePath.backupURL)
        try write(entries, to: TrustStorePath.url)
    }
}
