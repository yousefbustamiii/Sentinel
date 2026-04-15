import Foundation

/// Defines the operational interface for all Sentinel security scanners.
public protocol ScannerProtocol {
    var onResultDetected: ((ThreatEvaluator.DetectionResult) -> Void)? { get set }
    func start(interval: TimeInterval)
    func stop()
}
