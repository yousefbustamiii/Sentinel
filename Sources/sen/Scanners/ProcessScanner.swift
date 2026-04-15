import Foundation
import AppKit

/// Continuously monitors active processes for behavioral and structural anomalies.
public final class ProcessScanner: BaseScanner {
    
    public init() {
        super.init(label: "com.sentinel.processscanner")
    }

    override internal func performScan() {
        for app in NSWorkspace.shared.runningApplications {
            guard let name = app.localizedName,
                  let url = app.executableURL ?? app.bundleURL else { continue }

            let pid  = app.processIdentifier
            let path = url.path

            // Suppression Layer (Global Trust)
            guard !TrustManager.shared.isTrusted(path: path) else { continue }

            // Evidence Collection
            let context = HeuristicContextResolver.processContext(
                category: .process,
                name: name,
                pid: pid,
                path: path,
                uniqueID: url.uniqueID,
                app: app
            )
            let evidence = ProcessEvidenceBuilder.build(
                name: name,
                path: path,
                processId: pid,
                context: context
            )

            // Evaluation & Stateful Reporting
            evaluateAndReport(
                category: classifyThreat(from: evidence),
                name: name,
                path: path,
                uniqueID: url.uniqueID,
                evidence: evidence,
                processId: pid
            )
        }
    }

    /// Selects the most appropriate threat category based on the strength and combination of evidence.
    private func classifyThreat(from evidence: [Evidence]) -> ThreatCategory {
        let codes = Set(evidence.map(\.code))

        if codes.contains(.dylibInjection) {
            return .keylogger
        }

        if codes.contains(.knownToolMatch) && codes.contains(.anomalousPort) {
            return .rat
        }

        return .process
    }
}
