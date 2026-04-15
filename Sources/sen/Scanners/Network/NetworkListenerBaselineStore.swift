import Foundation

private struct NetworkListenerBaselineEntry: Codable {
    var firstSeenAt: Date
    var lastSeenAt: Date
    var observationCount: Int
}

final class NetworkListenerBaselineStore {
    static let shared = NetworkListenerBaselineStore()

    private let queue = DispatchQueue(label: "com.sentinel.networklistenerbaseline.store")
    private let retentionWindow: TimeInterval = 7 * 24 * 60 * 60
    private let maximumEntries = 512

    init() {}

    func observe(identity: String, now: Date = Date()) -> Bool {
        queue.sync {
            var state = loadState()
            prune(&state, now: now)

            var entry = state[identity] ?? NetworkListenerBaselineEntry(
                firstSeenAt: now,
                lastSeenAt: now,
                observationCount: 0
            )
            entry.lastSeenAt = now
            entry.observationCount += 1
            state[identity] = entry

            trimIfNeeded(&state)
            persist(state)
            return entry.observationCount > 1
        }
    }

    #if DEBUG
    func reset() {
        queue.sync {
            try? FileManager.default.removeItem(at: NetworkListenerBaselinePath.url)
        }
    }
    #endif

    private func loadState() -> [String: NetworkListenerBaselineEntry] {
        guard
            let data = try? Data(contentsOf: NetworkListenerBaselinePath.url),
            let decoded = try? StorageUtils.decoder.decode([String: NetworkListenerBaselineEntry].self, from: data)
        else {
            return [:]
        }
        return decoded
    }

    private func persist(_ state: [String: NetworkListenerBaselineEntry]) {
        do {
            let data = try StorageUtils.encoder.encode(state)
            try StorageUtils.writeAtomically(data, to: NetworkListenerBaselinePath.url)
        } catch {
            LogManager.record(LogEntry(
                eventName: "networkbaseline.failure",
                toolName: "NetworkListenerBaselineStore",
                severity: .warning,
                message: "Failed to persist network listener baseline state.",
                category: "network"
            ))
        }
    }

    private func prune(_ state: inout [String: NetworkListenerBaselineEntry], now: Date) {
        state = state.filter { now.timeIntervalSince($0.value.lastSeenAt) < retentionWindow }
    }

    private func trimIfNeeded(_ state: inout [String: NetworkListenerBaselineEntry]) {
        guard state.count > maximumEntries else { return }

        let sorted = state.sorted { $0.value.lastSeenAt > $1.value.lastSeenAt }
        state = Dictionary(
            uniqueKeysWithValues: sorted.prefix(maximumEntries).map { ($0.key, $0.value) }
        )
    }
}
