import Foundation

/// Semantic path provider for the unified Forensics log.
public struct LogStorePath {
    public static var url: URL {
        Configuration.shared.logURL
    }
}
