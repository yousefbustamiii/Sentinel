import Foundation

/// Manages the local trust store and provides boundary-aware path verification.
internal final class TrustManager {
    static let shared = TrustManager()
    
    private let queue = DispatchQueue(label: "com.sentinel.trustmanager", qos: .userInitiated)
    
    private enum StorageState {
        case notLoaded
        case loaded([TrustEntry])
    }
    
    private var state: StorageState = .notLoaded
    
    private init() {}
    
    /// Initializes the trust environment.
    func initialize() {
        queue.sync {
            StorageUtils.ensureDirectoryExists(for: TrustStorePath.url)
            load()
        }
    }

    #if DEBUG
    /// Resets the in-memory state. Used for testing only.
    func reset() {
        queue.sync {
            state = .notLoaded
        }
    }
    #endif
    
    /// Establishes trust for a given entry.
    func authorize(_ entry: TrustEntry) -> Bool {
        authorizeBatch([entry])
    }
    
    /// Establishes trust for multiple entries in a single atomic transaction.
    func authorizeBatch(_ newEntries: [TrustEntry]) -> Bool {
        queue.sync {
            var current = (try? getLoadedEntries()) ?? []
            
            for entry in newEntries {
                if let idx = current.firstIndex(where: { $0.path == entry.path }) {
                    current[idx] = entry
                } else {
                    current.append(entry)
                }
            }
            
            state = .loaded(current)
            return save(current)
        }
    }
    
    /// Removes trust for the entry at a specific index.
    func revoke(at index: Int) -> Bool {
        queue.sync {
            guard var current = try? getLoadedEntries(), index < current.count else { return false }
            current.remove(at: index)
            state = .loaded(current)
            return save(current)
        }
    }
    
    /// Retrieves all registered trust entries from the memory cache.
    var entries: [TrustEntry] {
        queue.sync { (try? getLoadedEntries()) ?? [] }
    }
    
    /// Performs a boundary-aware trust check for a given filesystem path.
    func isTrusted(path: String?) -> Bool {
        guard let pathString = path else { return false }
        return checkStatus(path: normalizedPath(pathString)) == .trusted
    }

    /// Checks if a specific Team ID is globally authorized.
    func isTrusted(teamID: String) -> Bool {
        let entries = queue.sync { (try? getLoadedEntries()) ?? [] }
        return entries.contains { $0.teamID == teamID && $0.kind.isSignerScope }
    }
    
    /// Determines the trust status of a path, accounting for tampering and bundle boundaries.
    func checkStatus(path: String) -> TrustStatus {
        let normalizedPath = normalizedPath(path)
        let queriedURL = URL(fileURLWithPath: normalizedPath)
        let queriedVolumeUUID = queriedURL.volumeUUID
        let entries = queue.sync { (try? getLoadedEntries()) ?? [] }

        let pathEntries = entries.filter { entry in
            TrustPathScope.matches(entry, queriedPath: normalizedPath, queriedVolumeUUID: queriedVolumeUUID)
        }

        var hasTrustedPathScope = false
        for entry in pathEntries {
            switch evaluatePathScopedEntry(entry) {
            case .trusted:
                hasTrustedPathScope = true
            case .tampered:
                return .tampered
            case .untrusted:
                continue
            }
        }

        if hasTrustedPathScope {
            return .trusted
        }

        let identity = CodeSignatureService.getIdentity(for: URL(fileURLWithPath: normalizedPath))
        if let teamID = identity.teamID,
           isTrusted(teamID: teamID),
           !CodeSignatureService.isUnverified(at: normalizedPath) {
            return .trusted
        }

        return .untrusted
    }
    
    // MARK: - Private
    
    private func getLoadedEntries() throws -> [TrustEntry] {
        switch state {
        case .loaded(let entries):
            return entries
        case .notLoaded:
            load()
            if case .loaded(let entries) = state { return entries }
            return []
        }
    }
    
    private func load() {
        for url in [TrustStorePath.url, TrustStorePath.backupURL] {
            guard let data = try? Data(contentsOf: url),
                  let decoded = try? StorageUtils.decoder.decode([TrustEntry].self, from: data) else {
                continue
            }

            state = .loaded(decoded)
            if url == TrustStorePath.backupURL {
                try? TrustStorePersistence.write(decoded, to: TrustStorePath.url)
            }
            return
        }
        state = .loaded([])
    }
    
    private func save(_ entries: [TrustEntry]) -> Bool {
        do {
            try TrustStorePersistence.persist(entries)
            return true
        } catch {
            return false
        }
    }

    private func normalizedPath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }

    private func evaluatePathScopedEntry(_ entry: TrustEntry) -> TrustStatus {
        if entry.kind.permitsPathTrustWithoutFingerprint {
            return .trusted
        }

        guard entry.kind.requiresPathFingerprint else {
            return .untrusted
        }

        guard let storedFingerprint = entry.fingerprint else {
            switch entry.updatePolicy {
            case .strict:
                return .tampered
            case .allowSignedUpdates:
                return validateSignedUpdate(for: entry)
            }
        }

        let currentFingerprint = TrustIntegritySnapshotResolver.currentFingerprint(for: entry)
        if let currentFingerprint, currentFingerprint == storedFingerprint {
            return .trusted
        }

        switch entry.updatePolicy {
        case .strict:
            return .tampered
        case .allowSignedUpdates:
            return validateSignedUpdate(for: entry)
        }
    }

    private func validateSignedUpdate(for entry: TrustEntry) -> TrustStatus {
        let identity = CodeSignatureService.getIdentity(for: URL(fileURLWithPath: entry.path))
        let isStillSignedBySameTeam = entry.teamID != nil && identity.teamID == entry.teamID
        let isSignatureValid = !CodeSignatureService.isUnverified(at: entry.path)

        return isStillSignedBySameTeam && isSignatureValid ? .trusted : .tampered
    }
}
