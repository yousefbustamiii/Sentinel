import Foundation
import AppKit

/// Orchestrates the lifecycle of all scanners and manages threat reporting.
public final class AgentCoordinator {
    private let processScanner = ProcessScanner()
    private let networkScanner = NetworkScanner()
    private let usbScanner = USBScanner()
    private let persistenceScanner = PersistenceScanner()

    public init() {}

    /// Initializes and activates the monitoring engine.
    public func start() {
        let config = Configuration.shared
        
        processScanner.onResultDetected     = { [weak self] result in self?.handle(result) }
        networkScanner.onResultDetected     = { [weak self] result in self?.handle(result) }
        usbScanner.onResultDetected         = { [weak self] result in self?.handle(result) }
        persistenceScanner.onResultDetected = { [weak self] result in self?.handle(result) }

        processScanner.start(interval: config.processInterval)
        networkScanner.start(interval: config.networkInterval)
        usbScanner.start(interval: config.usbInterval)
        persistenceScanner.start(interval: config.persistenceInterval)
    }

    // MARK: - Private

    private func handle(_ result: ThreatEvaluator.DetectionResult) {
        switch result {
        case .alert(let threat):       logAndAlert(threat)
        case .observation(let threat): logOnly(threat)
        case .none:                    break
        }
    }

    private func logAndAlert(_ threat: Threat) {
        let entry = LogEntry(
            eventName: "ThreatDetected",
            toolName: "SentinelAgent",
            severity: .error,
            message: "THREAT ALERT: \(threat.name). \(threat.explanation)",
            category: threat.category.rawValue,
            evidence: threat.evidence
        )
        LogManager.record(entry)
        _ = AlertManager.showThreatAlert(threat)
    }

    private func logOnly(_ threat: Threat) {
        let entry = LogEntry(
            eventName: "ObservationDetected",
            toolName: "SentinelAgent",
            severity: .info,
            message: "Observation: \(threat.name). \(threat.explanation)",
            category: threat.category.rawValue,
            evidence: threat.evidence
        )
        LogManager.record(entry)
    }
}
