import Foundation

/// Provides a lightweight cached view of LaunchAgent/LaunchDaemon binary targets.
final class PersistenceTargetIndex {
    static let shared = PersistenceTargetIndex()

    private let queue = DispatchQueue(label: "com.sentinel.persistencetargetindex")
    private let refreshInterval: TimeInterval = 30
    private let persistenceDirs: [String] = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        NSHomeDirectory() + "/Library/LaunchAgents"
    ]

    private var lastRefresh: Date?
    private var cachedTargets: Set<String> = []

    private init() {}

    func hasLaunchTarget(at path: String) -> Bool {
        let normalizedPath = URL(fileURLWithPath: path).resolvingSymlinksInPath().path

        return queue.sync {
            refreshIfNeeded()
            return cachedTargets.contains(normalizedPath)
        }
    }

    private func refreshIfNeeded() {
        if let lastRefresh, Date().timeIntervalSince(lastRefresh) < refreshInterval {
            return
        }

        var targets = Set<String>()
        for dir in persistenceDirs {
            let url = URL(fileURLWithPath: dir)
            let items = (try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []

            for item in items {
                guard let binaryPath = PersistenceManifestParser.snapshot(for: item)?.targetPath else { continue }
                targets.insert(URL(fileURLWithPath: binaryPath).resolvingSymlinksInPath().path)
            }
        }

        cachedTargets = targets
        lastRefresh = Date()
    }
}
