import Foundation

/// Converts a LogEntry into a human-readable string for terminal display.
public struct LogEntryFormatter {

    /// Returns the aligned, human-readable representation of a log entry.
    public static func format(_ entry: LogEntry) -> String {
        let sev = entry.extra.severity.rawValue.uppercased()
        let ts  = entry.timestamp.isoUtc
        let cat = entry.extra.category ?? entry.eventName
        let msg = entry.extra.message.isEmpty ? entry.eventName : entry.extra.message

        var lines = [
            "[\(sev)]",
            "[\(ts)]",
            "[\(cat)]",
            msg
        ]

        if let evidence = entry.extra.evidence, !evidence.isEmpty {
            lines.append("Evidence Trace:")
            lines.append(contentsOf: evidence.map { "  • \($0.description)" })
        }

        return lines.joined(separator: "\n")
    }
}
