import Foundation

/// Monitors for newly mounted removable media and assesses their risk profile.
public final class USBScanner: BaseScanner {
    
    private var knownVolumes: Set<String> = []

    public init() {
        super.init(label: "com.sentinel.usbscanner")
    }

    override public func start(interval: TimeInterval) {
        knownVolumes = currentVolumes()
        super.start(interval: interval)
    }

    override internal func performScan() {
        // Dev Mode: USB scanning suppressed entirely to avoid interrupting development workflows.
        guard !DevModeManager.shared.isActive() else { return }

        let volumes    = currentVolumes()
        let newVolumes = volumes.subtracting(knownVolumes)
        
        for volumePath in newVolumes {
            processVolume(path: volumePath)
        }
        
        knownVolumes = volumes
    }

    private func processVolume(path: String) {
        // Suppression Layer (Global Trust)
        guard !TrustManager.shared.isTrusted(path: path) else { return }

        let url = URL(fileURLWithPath: path)
        let name = url.lastPathComponent
        
        // Evidence Collection
        var evidence: [Evidence] = []

        if isKnownAttackHardware(name) {
            evidence.append(Evidence(code: .knownToolMatch, description: "Volume name matches known physical attack hardware characteristics.", source: .usb, context: name))
        }

        let contentEvidence = USBContentInspector.inspect(volume: url)
        evidence.append(contentsOf: contentEvidence)

        // Evaluation & Reporting
        let result = ThreatEvaluator.evaluate(
            category: .usb,
            name: name,
            path: path,
            evidence: evidence
        )

        if detectionState.shouldReport(identity: USBVolumeIdentity.sightingIdentity(for: url), level: result.level) {
            report(result)
        }
    }

    private func currentVolumes() -> Set<String> {
        let keys: [URLResourceKey] = [.volumeNameKey, .volumeIsRemovableKey]
        let paths: [URL] = FileManager.default.mountedVolumeURLs(includingResourceValuesForKeys: keys, options: []) ?? []
        
        var removablePaths: Set<String> = []
        for url in paths {
            let values = try? url.resourceValues(forKeys: Set(keys))
            if values?.volumeIsRemovable == true {
                removablePaths.insert(url.path)
            }
        }
        return removablePaths
    }

    internal func isKnownAttackHardware(_ name: String) -> Bool {
        let lower = name.lowercased()
        let devices = ["rubberducky", "bashbunny", "pwnagotchi", "hackrf", "lanturtle", "sharkjack", "flipper"]
        return devices.contains { lower.contains($0) }
    }
}
