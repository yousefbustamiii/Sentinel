import Foundation

struct StatusSnapshot {
    let isAgentLoaded: Bool
    let isDeveloperModeActive: Bool
    let developerModeDescription: String
    let trustEntryCount: Int
    let findingRecordCount: Int
    let lastAlertAt: Date?
    let lastLogAt: String?
    let hasCompletedPersistenceBaseline: Bool
    let persistenceItemCount: Int

    static func collect(isAgentLoaded: () -> Bool = { LaunchAgentService.shared.isRunning() }) -> StatusSnapshot {
        TrustManager.shared.initialize()

        let devState = DevModeManager.shared.currentState()
        let findings = FindingStore.shared.summary()
        let persistenceState = PersistenceStateStore.shared.currentState()
        let lastLogAt = LogManager.fetch(limit: 1).last?.timestamp.isoUtc

        return StatusSnapshot(
            isAgentLoaded: isAgentLoaded(),
            isDeveloperModeActive: devState != nil,
            developerModeDescription: devState?.remainingDescription ?? "Inactive",
            trustEntryCount: TrustManager.shared.entries.count,
            findingRecordCount: findings.recordCount,
            lastAlertAt: findings.lastAlertAt,
            lastLogAt: lastLogAt,
            hasCompletedPersistenceBaseline: persistenceState.hasCompletedInitialBaseline,
            persistenceItemCount: persistenceState.items.count
        )
    }
}
