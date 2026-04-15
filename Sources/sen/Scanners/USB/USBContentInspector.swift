import Foundation

/// Inspects the root level of a mounted volume for suspicious content indicators.
public struct USBContentInspector {
    /// Analyzes the contents of a newly mounted volume.
    public static func inspect(volume: URL) -> [Evidence] {
        var evidence: [Evidence] = []
        let path = volume.path

        do {
            let items = try FileManager.default.contentsOfDirectory(atPath: path)
            for itemName in items {
                let item = USBRootItemSnapshot(name: itemName)

                if item.isHidden && !USBContentRules.shouldIgnoreHiddenRootArtifact(item) {
                    evidence.append(Evidence(
                        code: .hiddenRootItem,
                        description: "Hidden item found at volume root: \(item.name)",
                        source: .usb,
                        context: item.name
                    ))
                }

                if USBContentRules.isContextuallySuspiciousFilename(item) {
                    evidence.append(Evidence(
                        code: .suspiciousFilename,
                        description: "Suspicious executable-like name found at volume root: \(item.name)",
                        source: .usb,
                        context: item.name
                    ))
                }

                if USBContentRules.shouldFlagExecutableAtRoot(item) {
                    evidence.append(Evidence(
                        code: .executableAtRoot,
                        description: "Executable or installer-like item found at volume root: \(item.name)",
                        source: .usb,
                        context: item.name
                    ))
                }
            }
        } catch {
            // Volume might have disconnected during scan
        }

        return evidence
    }
}
