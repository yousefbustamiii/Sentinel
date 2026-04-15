import Foundation

/// Semantic path provider for the findings state store and its recovery backup.
struct FindingStorePath {
    static var url: URL {
        Configuration.shared.findingsURL
    }

    static var backupURL: URL {
        url.deletingPathExtension().appendingPathExtension("json.bak")
    }
}
