import Foundation

/// Represents a validated security anomaly detected by a scanner.
public struct Threat: Codable, Equatable {
    public let category: ThreatCategory
    public let severity: ThreatSeverity
    public let confidence: ThreatConfidence
    public let name: String
    public let processId: Int32?
    public let explanation: String
    public let evidence: [Evidence]

    /// Summarizes the evidence collected for this threat in a human-readable format.
    public var evidenceSummary: String {
        evidence.map { $0.description }.joined(separator: ", ")
    }
}
