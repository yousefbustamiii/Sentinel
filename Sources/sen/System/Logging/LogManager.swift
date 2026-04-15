import Foundation

/// Primary façade for forensic logging operations within the Sentinel architecture.
internal struct LogManager {
    
    /// Initializes the forensics subsystem.
    static func initialize() {
        _ = LogStore.shared.readAll()
    }
    
    /// Synchronously retrieves every entry from the forensic data store.
    static func fetch(limit: Int? = nil) -> [LogEntry] {
        LogStore.shared.readAll(limit: limit)
    }
    
    /// Records a new log entry to the forensics store.
    static func record(_ entry: LogEntry) {
        LogStore.shared.append(entry)
    }
    
    /// Permanently wipes all forensic data from the system.
    static func wipe() {
        LogStore.shared.wipe()
    }
}
