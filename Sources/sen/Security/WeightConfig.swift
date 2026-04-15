import Foundation

/// Centralized configuration for heuristic threat scoring.
public struct WeightConfig {
    
    /// The score at which a finding is recorded as an observation.
    public static let observationThreshold = 2
    
    /// The score threshold required to escalate to an active security Alert.
    public static let alertThreshold = 8

    /// The reduction in score applied to binaries signed by Apple.
    public static let systemTrustCredit = 6
    
    /// Mapping of evidence codes to their relative severity weights.
    public static func weight(for code: Evidence.EvidenceCode) -> Int {
        switch code {
        // Critical Signals (5+)
        case .dylibInjection:    return 5
        case .tamperingDetected: return 10 // Immediate alert if trusted file is corrupted
        case .newPersistence:    return 4
        
        // Identity & Verification
        case .unverifiedIdentity: return 3
        case .unsignedBinary:     return 1
        
        // Structural Anomalies
        case .hiddenRootItem:     return 2
        case .pathAnomaly:        return 3
        case .executableAtRoot:   return 4
        case .searchPathExecution: return 3
        
        // Heuristic Matches
        case .suspiciousParent:   return 2
        case .anomalousPort:      return 2
        case .knownToolMatch:     return 1
        case .suspiciousFilename: return 2
        }
    }
}
