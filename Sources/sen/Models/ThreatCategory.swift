import Foundation

/// Defines the broad classification of a security threat.
public enum ThreatCategory: String, Codable, Equatable {
    case process     = "PROCESS"
    case rat         = "RAT"
    case keylogger   = "KEYLOGGER"
    case network     = "NETWORK"
    case usb         = "USB"
    case persistence = "PERSISTENCE"
}
