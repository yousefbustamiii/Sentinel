import Foundation

/// Scans for suspicious network listeners using structured `lsof` output and native pid path resolution.
public final class NetworkScanner: BaseScanner {
    private let baseline = NetworkListenerBaseline()

    public init() {
        super.init(label: "com.sentinel.networkscanner")
    }

    override internal func performScan() {
        do {
            let result = try NetworkListenerCollector.collect()
            if result.exitCode != 0 && !result.stderr.isEmpty {
                logFailure("lsof exited with status \(result.exitCode): \(result.stderr)")
            }
            processListeners(result.listeners)
        } catch {
            logFailure("Failed to collect network listeners: \(error.localizedDescription)")
        }
    }

    private func processListeners(_ listeners: [NetworkListenerSnapshot]) {
        for listener in listeners {
            let path = NetworkProcessInfoResolver.executablePath(for: listener.processIdentifier)
            let app = NetworkProcessInfoResolver.runningApplication(for: listener.processIdentifier)
            let url = path.map { URL(fileURLWithPath: $0) }
            let isRecurring = baseline.observe(listener)

            if let resolvedPath = path, TrustManager.shared.isTrusted(path: resolvedPath) {
                continue
            }

            if NetworkListenerHeuristics.shouldIgnore(listener: listener, executablePath: path) {
                continue
            }

            let context = HeuristicContextResolver.networkContext(
                category: .network,
                name: listener.processName,
                pid: listener.processIdentifier,
                path: path,
                uniqueID: url?.uniqueID,
                app: app,
                listenerPort: listener.endpointPort,
                userID: listener.userID,
                userName: listener.userName,
                isLocalOnlyListener: listener.isLocalOnly,
                hasResolvedExecutablePath: path != nil,
                isRecurringListener: isRecurring
            )

            let isSignatureValid = context.isSignatureValid
            guard NetworkListenerHeuristics.hasMeaningfulNetworkSignal(
                listener: listener,
                hasExecutablePath: path != nil,
                isRecurring: isRecurring,
                isSignatureValid: isSignatureValid
            ) else {
                continue
            }

            var evidence: [Evidence] = []

            if let portEvidence = HeuristicEngine.checkPortAnomaly(
                "\(listener.endpointHost):\(listener.endpointPort)",
                source: .network,
                context: context
            ) {
                evidence.append(portEvidence)
            }

            if path != nil,
               let nameEvidence = HeuristicEngine.checkNameAnomaly(
                name: listener.processName,
                source: .network,
                context: context
               ) {
                evidence.append(nameEvidence)
            }

            if let resolvedPath = path,
               let pathEvidence = HeuristicEngine.checkPathAnomaly(
                path: resolvedPath,
                source: .network,
                context: context
               ) {
                evidence.append(pathEvidence)
            }

            if !isSignatureValid {
                evidence.append(Evidence(
                    code: .unverifiedIdentity,
                    description: "Network listener fails cryptographic identity checks.",
                    source: .network
                ))
            }

            guard !evidence.isEmpty else { continue }

            let listenerKey = [
                String(listener.processIdentifier),
                listener.endpointHost,
                String(listener.endpointPort),
                listener.userName ?? listener.userID.map(String.init) ?? "unknown"
            ].joined(separator: "|")

            let result = ThreatEvaluator.evaluate(
                category: .network,
                name: listener.processName,
                processId: listener.processIdentifier,
                path: path,
                uniqueID: url?.uniqueID,
                evidence: evidence
            )

            if detectionState.shouldReport(identity: listenerKey, level: result.level) {
                report(result)
            }
        }
    }

    private func logFailure(_ message: String) {
        LogManager.record(LogEntry(
            eventName: "networkscanner.failure",
            toolName: "NetworkScanner",
            severity: .warning,
            message: message,
            category: "scanner"
        ))
    }
}
