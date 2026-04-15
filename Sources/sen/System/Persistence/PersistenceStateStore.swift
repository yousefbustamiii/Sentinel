import Foundation

struct PersistenceTrackedItem: Codable, Equatable {
    let path: String
    let fileHash: String?
    let targetPath: String?
    let signerTeamID: String?
    let lastModified: Date?
    var everReviewed: Bool
    let isValidPropertyList: Bool

    init(snapshot: PersistenceManifestSnapshot, everReviewed: Bool) {
        self.path = snapshot.path
        self.fileHash = snapshot.fileHash
        self.targetPath = snapshot.targetPath
        self.signerTeamID = snapshot.signerTeamID
        self.lastModified = snapshot.lastModified
        self.everReviewed = everReviewed
        self.isValidPropertyList = snapshot.isValidPropertyList
    }
}

private struct PersistenceState: Codable {
    var hasCompletedInitialBaseline: Bool
    var items: [String: PersistenceTrackedItem]
}

final class PersistenceStateStore {
    static let shared = PersistenceStateStore()

    private let queue = DispatchQueue(label: "com.sentinel.persistencestatestore", qos: .userInitiated)
    private var loadedURL: URL?
    private var state = PersistenceState(hasCompletedInitialBaseline: false, items: [:])

    private init() {}

    func currentState() -> (hasCompletedInitialBaseline: Bool, items: [String: PersistenceTrackedItem]) {
        queue.sync {
            loadIfNeeded()
            return (state.hasCompletedInitialBaseline, state.items)
        }
    }

    func bootstrap(with snapshots: [PersistenceManifestSnapshot]) {
        queue.sync {
            loadIfNeeded()
            state.hasCompletedInitialBaseline = true
            state.items = Dictionary(
                uniqueKeysWithValues: snapshots.map { ($0.path, PersistenceTrackedItem(snapshot: $0, everReviewed: false)) }
            )
            save()
        }
    }

    func update(snapshot: PersistenceManifestSnapshot, everReviewed: Bool) {
        queue.sync {
            loadIfNeeded()
            state.items[snapshot.path] = PersistenceTrackedItem(snapshot: snapshot, everReviewed: everReviewed)
            save()
        }
    }

    func prune(to existingPaths: Set<String>) {
        queue.sync {
            loadIfNeeded()
            state.items = state.items.filter { existingPaths.contains($0.key) }
            save()
        }
    }

    #if DEBUG
    func reset() {
        queue.sync {
            loadedURL = nil
            state = PersistenceState(hasCompletedInitialBaseline: false, items: [:])
        }
    }
    #endif

    private func loadIfNeeded() {
        let currentURL = PersistenceStatePath.url
        guard loadedURL != currentURL else { return }

        StorageUtils.ensureDirectoryExists(for: currentURL)
        loadedURL = currentURL

        for url in [PersistenceStatePath.url, PersistenceStatePath.backupURL] {
            guard let data = try? Data(contentsOf: url),
                  let decoded = try? StorageUtils.decoder.decode(PersistenceState.self, from: data) else {
                continue
            }

            state = decoded
            if url == PersistenceStatePath.backupURL {
                let encoded = try? StorageUtils.encoder.encode(decoded)
                if let encoded {
                    try? PersistenceStatePersistence.write(encoded, to: PersistenceStatePath.url)
                }
            }
            return
        }

        state = PersistenceState(hasCompletedInitialBaseline: false, items: [:])
    }

    private func save() {
        guard loadedURL != nil else { return }

        do {
            let data = try StorageUtils.encoder.encode(state)
            try PersistenceStatePersistence.persist(data)
        } catch {
            LogManager.record(LogEntry(
                eventName: "persistencescanner.failure",
                toolName: "PersistenceStateStore",
                severity: .warning,
                message: "Failed to persist persistence state store.",
                category: "persistence"
            ))
        }
    }
}
