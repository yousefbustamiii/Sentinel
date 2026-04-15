import Foundation

internal final class LogStore {
    static let shared = LogStore()

    private let queue = DispatchQueue(label: "com.sentinel.logstore", qos: .utility)
    private let maxFileSizeBytes = 512 * 1024
    private let defaultReadLimit = 1000

    internal init() {
        StorageUtils.ensureDirectoryExists(for: LogStorePath.url)
        ensureHardenedLogFileIfNeeded()
    }

    /// Reads recent log entries from the persistent store, recovering from a truncated final line.
    func readAll(limit: Int? = nil) -> [LogEntry] {
        queue.sync {
            let files = existingLogFiles()
            let entries = files.flatMap(LogStoreReader.readEntries)
            let boundedLimit = limit ?? defaultReadLimit

            if entries.count <= boundedLimit {
                return entries
            }

            return Array(entries.suffix(boundedLimit))
        }
    }

    /// Appends a log entry synchronously with file locking, rotation, and fsync-backed durability.
    func append(_ entry: LogEntry) {
        queue.sync {
            do {
                try rotateIfNeeded(for: entry)
                try LogStoreWriter.append(entry, to: LogStorePath.url)
            } catch {
                fputs("Sentinel [Error]: Failed to append to forensics log.\n", stderr)
            }
        }
    }

    /// Securely wipes the forensics database.
    func wipe() {
        queue.sync {
            try? FileManager.default.removeItem(at: LogStorePath.url)
            try? FileManager.default.removeItem(at: rotatedLogURL)
        }
    }

    private var rotatedLogURL: URL {
        LogStorePath.url.deletingPathExtension().appendingPathExtension("log.1")
    }

    private func existingLogFiles() -> [URL] {
        [rotatedLogURL, LogStorePath.url].filter { FileManager.default.fileExists(atPath: $0.path) }
    }

    private func ensureHardenedLogFileIfNeeded() {
        guard !FileManager.default.fileExists(atPath: LogStorePath.url.path) else {
            LogStoreWriter.hardenPermissions(at: LogStorePath.url)
            return
        }

        FileManager.default.createFile(atPath: LogStorePath.url.path, contents: nil)
        LogStoreWriter.hardenPermissions(at: LogStorePath.url)
    }

    private func rotateIfNeeded(for entry: LogEntry) throws {
        let entrySize = try StorageUtils.encoder.encode(entry).count + 1
        let currentSize = (try? FileManager.default.attributesOfItem(atPath: LogStorePath.url.path)[.size] as? NSNumber)?.intValue ?? 0
        guard currentSize + entrySize > maxFileSizeBytes else { return }

        try? FileManager.default.removeItem(at: rotatedLogURL)

        if FileManager.default.fileExists(atPath: LogStorePath.url.path) {
            try FileManager.default.moveItem(at: LogStorePath.url, to: rotatedLogURL)
            LogStoreWriter.hardenPermissions(at: rotatedLogURL)
        }

        FileManager.default.createFile(atPath: LogStorePath.url.path, contents: nil)
        LogStoreWriter.hardenPermissions(at: LogStorePath.url)
    }
}
