import Foundation

enum StatusFormatter {
    static func rows(for snapshot: StatusSnapshot) -> [(label: String, value: String, style: TerminalUI.Style)] {
        [
            ("Agent", snapshot.isAgentLoaded ? "Loaded" : "Inactive", snapshot.isAgentLoaded ? .success : .muted),
            ("Developer Mode", snapshot.isDeveloperModeActive ? snapshot.developerModeDescription : "Inactive", snapshot.isDeveloperModeActive ? .warning : .muted),
            ("Trusted Entries", String(snapshot.trustEntryCount), .standard),
            ("Findings Stored", String(snapshot.findingRecordCount), .standard),
            ("Last Alert", formatted(date: snapshot.lastAlertAt) ?? "Never", .standard),
            ("Last Log Event", snapshot.lastLogAt ?? "None", .standard),
            (
                "Persistence State",
                snapshot.hasCompletedPersistenceBaseline
                    ? "Baseline ready (\(snapshot.persistenceItemCount) items)"
                    : "Initial baseline pending",
                snapshot.hasCompletedPersistenceBaseline ? .standard : .warning
            )
        ]
    }

    static func formatted(date: Date?) -> String? {
        guard let date else { return nil }
        let formatter = ISO8601DateFormatter()
        return formatter.string(from: date)
    }
}
