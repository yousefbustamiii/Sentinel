import Foundation

/// Base infrastructure for all Sentinel security scanners.
/// Provides standardized timer management and concurrency handling.
public class BaseScanner: ScannerProtocol {
    public var onResultDetected: ((ThreatEvaluator.DetectionResult) -> Void)?
    
    internal var timer: DispatchSourceTimer?
    internal let queue: DispatchQueue
    
    /// Internal reporting state to manage detection escalation.
    internal var detectionState = DetectionState()
    
    public init(label: String) {
        self.queue = DispatchQueue(label: label, qos: .background)
    }
    
    public func start(interval: TimeInterval) {
        timer = makeTimer(interval: interval, queue: queue) { [weak self] in
            self?.performScan()
        }
    }
    
    public func stop() {
        timer?.cancel()
        timer = nil
    }
    
    /// Subclasses must override this to perform the actual security assessment.
    internal func performScan() {
        fatalError("BaseScanner.performScan() must be overridden by specialized scanner.")
    }

    /// Standard GCD Timer setup for scanners to ensure consistent execution.
    internal func makeTimer(interval: TimeInterval, queue: DispatchQueue, handler: @escaping () -> Void) -> DispatchSourceTimer {
        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now(), repeating: interval, leeway: .milliseconds(500))
        timer.setEventHandler { handler() }
        timer.resume()
        return timer
    }

    /// Standardizes reporting back to the coordinator on the main thread.
    internal func report(_ result: ThreatEvaluator.DetectionResult) {
        DispatchQueue.main.async {
            self.onResultDetected?(result)
        }
    }

    /// Encapsulates the entire security evaluation and stateful reporting lifecycle.
    internal func evaluateAndReport(
        category: ThreatCategory,
        name: String,
        path: String?,
        uniqueID: String?,
        evidence: [Evidence],
        processId: Int32? = nil
    ) {
        let result = ThreatEvaluator.evaluate(
            category: category,
            name: name,
            processId: processId,
            path: path,
            uniqueID: uniqueID,
            evidence: evidence
        )
        
        let identity = SightingIdentity(category: category.rawValue, name: name, path: path, uniqueID: uniqueID).uniqueID
        
        if detectionState.shouldReport(identity: identity, level: result.level) {
            report(result)
        }
    }
}
