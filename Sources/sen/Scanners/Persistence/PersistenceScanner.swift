import Foundation

/// Monitors system launch directories for new, changed, and suspicious persistence items.
public final class PersistenceScanner: BaseScanner {
    private let persistenceDirs: [String]
    private let stateStore: PersistenceStateStore

    public init() {
        self.persistenceDirs = [
            "/Library/LaunchAgents",
            "/Library/LaunchDaemons",
            NSHomeDirectory() + "/Library/LaunchAgents"
        ]
        self.stateStore = .shared
        super.init(label: "com.sentinel.persistencescanner")
    }

    internal init(
        persistenceDirs: [String],
        stateStore: PersistenceStateStore = .shared
    ) {
        self.persistenceDirs = persistenceDirs
        self.stateStore = stateStore
        super.init(label: "com.sentinel.persistencescanner")
    }

    override public func start(interval: TimeInterval) {
        performInitialBaselineIfNeeded()
        super.start(interval: interval)
    }

    override internal func performScan() {
        let snapshots = currentSnapshots()
        let currentPaths = Set(snapshots.map(\.path))
        let storedState = stateStore.currentState()

        if !storedState.hasCompletedInitialBaseline {
            stateStore.bootstrap(with: snapshots)
            return
        }

        for snapshot in snapshots {
            process(snapshot: snapshot, previous: storedState.items[snapshot.path])
        }

        stateStore.prune(to: currentPaths)
    }

    internal func getBinaryTarget(from plist: URL) -> String? {
        PersistenceManifestParser.snapshot(for: plist)?.targetPath
    }

    internal func currentSnapshots() -> [PersistenceManifestSnapshot] {
        persistenceDirs.flatMap { dir in
            let url = URL(fileURLWithPath: dir)
            let items = (try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil)) ?? []
            return items.compactMap(PersistenceManifestParser.snapshot(for:))
        }
    }

    private func performInitialBaselineIfNeeded() {
        let storedState = stateStore.currentState()
        guard !storedState.hasCompletedInitialBaseline else { return }
        stateStore.bootstrap(with: currentSnapshots())
    }

    private func process(snapshot: PersistenceManifestSnapshot, previous: PersistenceTrackedItem?) {
        let path = snapshot.path
        guard !TrustManager.shared.isTrusted(path: path) else { return }

        let changeKind = classifyChange(snapshot: snapshot, previous: previous)
        let shouldEvaluateSuspicion = previous.map { !$0.everReviewed } ?? false
        guard changeKind != nil || shouldEvaluateSuspicion else { return }

        var evidence = evidenceForSnapshot(snapshot, changeKind: changeKind)
        let uniqueID = snapshot.targetPath.map { URL(fileURLWithPath: $0).uniqueID }

        if let targetPath = snapshot.targetPath {
            let context = HeuristicContextResolver.persistenceContext(
                category: .persistence,
                name: URL(fileURLWithPath: targetPath).lastPathComponent,
                path: targetPath,
                uniqueID: uniqueID ?? nil
            )

            if CodeSignatureService.isUnverified(at: targetPath) {
                evidence.append(Evidence(
                    code: .unverifiedIdentity,
                    description: "Persistence target binary identity is unverified.",
                    source: .persistence
                ))
            }

            if let pathEvidence = HeuristicEngine.checkPathAnomaly(path: targetPath, source: .persistence, context: context) {
                evidence.append(pathEvidence)
            }

            if let nameEvidence = HeuristicEngine.checkNameAnomaly(
                name: URL(fileURLWithPath: targetPath).deletingPathExtension().lastPathComponent,
                source: .persistence,
                context: context
            ) {
                evidence.append(nameEvidence)
            }
        }

        guard !evidence.isEmpty else {
            stateStore.update(snapshot: snapshot, everReviewed: true)
            return
        }

        evaluateAndReport(
            category: .persistence,
            name: URL(fileURLWithPath: path).lastPathComponent,
            path: path,
            uniqueID: uniqueID ?? nil,
            evidence: evidence
        )

        stateStore.update(snapshot: snapshot, everReviewed: true)
    }

    private func classifyChange(snapshot: PersistenceManifestSnapshot, previous: PersistenceTrackedItem?) -> String? {
        guard let previous else { return "new file" }

        if previous.fileHash != snapshot.fileHash { return "changed file" }
        if previous.targetPath != snapshot.targetPath { return "changed target" }
        if previous.signerTeamID != snapshot.signerTeamID { return "changed signer" }
        if previous.isValidPropertyList != snapshot.isValidPropertyList { return "changed plist validity" }
        return nil
    }

    private func evidenceForSnapshot(_ snapshot: PersistenceManifestSnapshot, changeKind: String?) -> [Evidence] {
        var evidence: [Evidence] = []

        if let changeKind {
            let code: Evidence.EvidenceCode = changeKind == "new file" ? .newPersistence : .tamperingDetected
            let description = changeKind == "new file"
                ? "New launch configuration item detected."
                : "Persistence manifest \(changeKind)."

            evidence.append(Evidence(code: code, description: description, source: .persistence, context: snapshot.path))
        }

        if !snapshot.isValidPropertyList {
            evidence.append(Evidence(
                code: .tamperingDetected,
                description: snapshot.parseError ?? "Persistence manifest is corrupted.",
                source: .persistence,
                context: snapshot.path
            ))
        }

        return evidence
    }
}
