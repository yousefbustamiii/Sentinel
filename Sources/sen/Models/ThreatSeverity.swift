import Foundation

/// How impactful this threat category is if confirmed.
public enum ThreatSeverity: String, Codable {
    case info    = "info"
    case low     = "low"
    case medium  = "medium"
    case high    = "high"
}
