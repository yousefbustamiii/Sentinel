import Foundation

/// Represents a persistent record of a security anomaly or process sighting.
public struct FindingRecord: Codable {
    public let id: String
    public let firstSeen: Date
    public var lastSeen: Date
    public var count: Int
    public var lastAlertedAt: Date?

    public init(id: String) {
        self.id = id
        self.firstSeen = Date()
        self.lastSeen = Date()
        self.count = 1
        self.lastAlertedAt = nil
    }
}

/// Manages persistent storage of security findings with validated recovery and atomic saves.
public final class FindingStore {
    public static let shared = FindingStore()

    private let queue = DispatchQueue(label: "com.sentinel.findingstore")
    private var findings: [String: FindingRecord] = [:]
    private var loadedURL: URL?

    private init() {
        queue.sync {
            StorageUtils.ensureDirectoryExists(for: FindingStorePath.url)
            loadFindingsFromDisk()
        }
    }

    /// Records a security sighting and returns the updated record.
    public func record(category: String, name: String, path: String?, uniqueID: String? = nil) -> FindingRecord {
        queue.sync {
            ensureLoaded()

            let id = SightingIdentity(category: category, name: name, path: path, uniqueID: uniqueID).uniqueID

            var record = findings[id] ?? FindingRecord(id: id)
            if findings[id] != nil {
                record.count += 1
                record.lastSeen = Date()
            }

            findings[id] = record
            persistToDisk()
            return record
        }
    }

    /// Updates the alert timestamp for a specific sighting.
    public func markAlerted(id: String) {
        queue.sync {
            ensureLoaded()

            if var record = findings[id] {
                record.lastAlertedAt = Date()
                findings[id] = record
                persistToDisk()
            }
        }
    }

    /// Returns an existing sighting record without mutating counters or timestamps.
    public func existingRecord(category: String, name: String, path: String?, uniqueID: String? = nil) -> FindingRecord? {
        queue.sync {
            ensureLoaded()
            let id = SightingIdentity(category: category, name: name, path: path, uniqueID: uniqueID).uniqueID
            return findings[id]
        }
    }

    func summary() -> (recordCount: Int, lastAlertAt: Date?) {
        queue.sync {
            ensureLoaded()
            let lastAlertAt = findings.values.compactMap(\.lastAlertedAt).max()
            return (findings.count, lastAlertAt)
        }
    }

    #if DEBUG
    func reset() {
        queue.sync {
            findings = [:]
            loadedURL = nil
        }
    }

    func flushForTesting() {
        queue.sync {
            ensureLoaded()
            persistToDisk()
        }
    }
    #endif

    // MARK: - Private

    private func ensureLoaded() {
        let currentURL = FindingStorePath.url
        guard loadedURL != currentURL else { return }

        StorageUtils.ensureDirectoryExists(for: currentURL)
        loadedURL = currentURL
        loadFindingsFromDisk()
    }

    private func loadFindingsFromDisk() {
        let urls = [FindingStorePath.url, FindingStorePath.backupURL]
        var attemptedRecovery = false

        for url in urls {
            guard let data = try? Data(contentsOf: url) else { continue }
            attemptedRecovery = true

            do {
                let decoded = try StorageUtils.decoder.decode([String: FindingRecord].self, from: data)
                let validated = try FindingStoreValidator.validate(decoded)
                findings = validated

                if url == FindingStorePath.backupURL {
                    do {
                        try FindingStorePersistence.write(validated, to: FindingStorePath.url)
                        logRecovery("Recovered findings database from backup file.")
                    } catch {
                        logRecovery("Recovered findings from backup, but failed to rewrite primary database: \(error.localizedDescription)")
                    }
                }

                return
            } catch {
                logRecovery("Failed to decode findings database at \(url.lastPathComponent): \(error.localizedDescription)")
            }
        }

        findings = [:]
        if attemptedRecovery {
            logRecovery("Starting with an empty findings database after recovery failure.")
        }
    }

    private func persistToDisk() {
        do {
            try FindingStorePersistence.persist(findings)
        } catch {
            logRecovery("Failed to persist findings database: \(error.localizedDescription)")
        }
    }

    private func logRecovery(_ message: String) {
        fputs("Sentinel [Warning]: \(message)\n", stderr)
    }
}
