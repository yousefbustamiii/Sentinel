import AppKit
import Foundation

/// Orchestrates the presentation of security alerts to the user.
internal final class AlertManager {
    
    /// User responses to a security alert.
    enum UserAction {
        case acknowledged
        case aborted
    }
    
    /// Displays a critical system alert for a detected security threat.
    static func showThreatAlert(_ threat: Threat) -> UserAction {
        let alert = NSAlert()
        alert.messageText = "Sentinel | \(threat.category.rawValue)"
        alert.informativeText = buildInformativeText(for: threat)
        alert.alertStyle = .critical
        alert.addButton(withTitle: "Acknowledge")
        
        return alert.runModal() == .alertFirstButtonReturn ? .acknowledged : .aborted
    }
    
    // MARK: - Private Formatting
    
    private static func buildInformativeText(for threat: Threat) -> String {
        """
        Detection: \(threat.name)
        
        \(threat.explanation)
        
        Evidence Summary:
        \(formatEvidence(threat.evidence))
        """
    }
    
    private static func formatEvidence(_ evidence: [Evidence]) -> String {
        evidence.map { "• \($0.description)" }.joined(separator: "\n")
    }
}
