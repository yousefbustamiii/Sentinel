import Foundation

/// Defines the source scanners for security evidence to ensure consistency.
public enum ScannerSource: String, Codable {
    case process     = "ProcessScanner"
    case network     = "NetworkScanner"
    case usb         = "USBScanner"
    case persistence = "PersistenceScanner"
}
