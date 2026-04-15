import Foundation

/// Encapsulates the stateful reporting lifecycle of scan detections.
/// Ensures that alerts are only escalated when detection severity increases.
public struct DetectionState {
    private var reportedLevels: [String: ThreatEvaluator.GatingLevel] = [:]
    
    public init() {}
    
    /// Evaluates if the given detection result should be reported based on previous state.
    /// If reporting is warranted, updates the internal state and returns true.
    public mutating func shouldReport(identity: String, level: ThreatEvaluator.GatingLevel) -> Bool {
        let lastLevel = reportedLevels[identity] ?? .none
        
        guard level > .none && level > lastLevel else {
            return false
        }
        
        reportedLevels[identity] = level
        return true
    }
}
