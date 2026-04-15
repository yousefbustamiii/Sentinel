import Foundation

/// Analyzes evidence to determine the severity and nature of a security finding.
public struct ThreatEvaluator {
    
    /// Defines the hierarchical gating level of a detection to manage reporting state.
    public enum GatingLevel: Int, Comparable {
        case none        = 0
        case observation = 1
        case alert       = 2
        
        public static func < (lhs: GatingLevel, rhs: GatingLevel) -> Bool {
            lhs.rawValue < rhs.rawValue
        }
    }
    
    public enum DetectionResult {
        case none
        case observation(Threat)
        case alert(Threat)
        
        /// Retreives the gating level for this result.
        public var level: GatingLevel {
            switch self {
            case .alert:       return .alert
            case .observation: return .observation
            case .none:        return .none
            }
        }
    }

    /// Evaluates a collection of evidence and returns a tiered detection decision.
    public static func evaluate(
        category: ThreatCategory,
        name: String,
        processId: Int32? = nil,
        path: String? = nil,
        uniqueID: String? = nil,
        evidence: [Evidence]
    ) -> DetectionResult {
        // 0. Global Trust Layer: Skip everything already verified by system policy.
        if let p = path, TrustManager.shared.isTrusted(path: p) {
            return .none
        }

        let totalScore = evidence.reduce(0) { $0 + WeightConfig.weight(for: $1.code) }
        let finalScore = ThreatScoring.applySystemTrustCredit(totalScore: totalScore, path: path)

        // Persistent Sighting Management
        let record = FindingStore.shared.record(category: category.rawValue, name: name, path: path, uniqueID: uniqueID)

        // Threshold Decision Logic
        if finalScore >= WeightConfig.alertThreshold {
            let threat = buildThreat(category: category, name: name, pid: processId, evidence: evidence, score: finalScore)
            
            // Re-alerting Gating: Only escalate to alert if the debounce interval has passed.
            let debounce: TimeInterval = DevModeManager.shared.isActive() ? 300 : 3600
            if let lastAlert = record.lastAlertedAt, Date().timeIntervalSince(lastAlert) < debounce {
                return .observation(threat)
            }
            
            FindingStore.shared.markAlerted(id: record.id)
            return .alert(threat)
            
        } else if finalScore >= WeightConfig.observationThreshold {
            let threat = buildThreat(category: category, name: name, pid: processId, evidence: evidence, score: finalScore)
            return .observation(threat)
        }

        return .none
    }

    private static func buildThreat(
        category: ThreatCategory,
        name: String,
        pid: Int32?,
        evidence: [Evidence],
        score: Int
    ) -> Threat {
        let severity: ThreatSeverity = score >= 15 ? .high : (score >= 8 ? .medium : .low)
        let confidence: ThreatConfidence = calculateConfidence(evidence: evidence, score: score)
        let explanation = generateExplanation(evidence: evidence, category: category)
        
        return Threat(
            category: category,
            severity: severity,
            confidence: confidence,
            name: name,
            processId: pid,
            explanation: explanation,
            evidence: evidence
        )
    }

    private static func calculateConfidence(evidence: [Evidence], score: Int) -> ThreatConfidence {
        let count = evidence.count
        if count >= 3 && score >= 12 { return .strong }
        if count >= 2 || score >= 6 { return .moderate }
        return .weak
    }

    private static func generateExplanation(evidence: [Evidence], category: ThreatCategory) -> String {
        if evidence.isEmpty {
            return defaultExplanation(for: category)
        }
        
        let sorted = evidence.sorted { WeightConfig.weight(for: $0.code) > WeightConfig.weight(for: $1.code) }
        if let primary = sorted.first {
            return "Detected \(category.rawValue.lowercased()) risk: \(primary.description)"
        }
        
        return defaultExplanation(for: category)
    }

    private static func defaultExplanation(for category: ThreatCategory) -> String {
        switch category {
        case .process:     return "Suspicious process execution detected — generic behavioral anomaly."
        case .rat:         return "Process matches Remote Access Tool behavioral patterns."
        case .keylogger:   return "Event suggests potential keyboard or input interception."
        case .network:     return "Suspicious network listener with unverified characteristics."
        case .usb:         return "Removable volume mount with suspicious metadata."
        case .persistence: return "Suspicious launch configuration detected."
        }
    }
}
