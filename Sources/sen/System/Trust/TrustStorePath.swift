import Foundation

/// Semantic path provider for the unified Trust store.
public struct TrustStorePath {
    public static var url: URL {
        Configuration.shared.trustURL
    }

    public static var backupURL: URL {
        url.deletingPathExtension().appendingPathExtension("json.bak")
    }
}
