import Foundation

/// Severity level for a log entry.
public enum LogSeverity: String, Codable {
    case debug   = "debug"
    case info    = "info"
    case success = "success"
    case warning = "warning"
    case error   = "error"
}
