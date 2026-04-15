import Foundation

/// How confident Sentinel is that this is a real threat, based on evidence count and quality.
public enum ThreatConfidence: String, Codable {
    case weak     = "weak"
    case moderate = "moderate"
    case strong   = "strong"
}
