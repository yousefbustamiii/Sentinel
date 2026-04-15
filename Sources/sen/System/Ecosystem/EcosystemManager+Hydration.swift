import Foundation

extension EcosystemManager {
    /// Scans supported ecosystems and pins their current state into the trust store.
    @discardableResult
    public static func hydrate(using paths: [String]? = nil) -> HydrationReport {
        let sources = resolveSources(using: paths)
        var entries: [TrustEntry] = []
        var skippedEntries = 0

        for source in sources {
            let url = URL(fileURLWithPath: source.path)
            let allowedPrefixes = allowedPrefixes(for: source.path, provenance: source.provenance)

            if source.provenance == .homebrewArm64 || source.provenance == .homebrewUsrLocal {
                guard verifyHomebrewIntegrity(root: url.deletingLastPathComponent()) else { continue }
            }

            guard let files = try? FileManager.default.contentsOfDirectory(at: url, includingPropertiesForKeys: nil) else {
                continue
            }

            var seenPaths = Set<String>()
            for fileURL in files {
                guard let candidate = candidateEntry(
                    for: fileURL,
                    provenance: source.provenance,
                    allowedPrefixes: allowedPrefixes
                ) else {
                    skippedEntries += 1
                    continue
                }
                guard seenPaths.insert(candidate.path).inserted else { continue }

                let entry = TrustEntry(
                    kind: .ecosystem,
                    path: candidate.path,
                    fingerprint: candidate.fingerprint,
                    bundleID: candidate.bundleID,
                    teamID: candidate.teamID,
                    provenance: candidate.provenance,
                    resolvedPath: candidate.path,
                    fileType: candidate.fileType,
                    ownerUserID: candidate.ownerUserID,
                    ownerGroupID: candidate.ownerGroupID,
                    updatePolicy: .strict
                )
                entries.append(entry)
            }
        }

        if !entries.isEmpty {
            _ = TrustManager.shared.authorizeBatch(entries)
        }

        return HydrationReport(addedEntries: entries.count, skippedEntries: skippedEntries)
    }

    static func resolveSources(using paths: [String]?) -> [(path: String, provenance: Provenance)] {
        if let paths {
            return paths.map { path in
                (path: path, provenance: inferredProvenance(for: path))
            }
        }

        return defaultProvenances.map { provenance in
            (path: provenance.scanPath, provenance: provenance)
        }
    }

    static func inferredProvenance(for path: String) -> Provenance {
        if path.contains("/opt/homebrew/") { return .homebrewArm64 }
        if path.contains("/usr/local/") { return .homebrewUsrLocal }
        return .nixProfile
    }

    static func allowedPrefixes(for scanPath: String, provenance: Provenance) -> [String] {
        switch provenance {
        case .homebrewArm64, .homebrewUsrLocal:
            let root = URL(fileURLWithPath: scanPath).deletingLastPathComponent().path
            return [
                root + "/Cellar/",
                root + "/bin/"
            ]
        case .nixProfile:
            return [
                "/nix/store/",
                URL(fileURLWithPath: scanPath).deletingLastPathComponent().path + "/"
            ]
        }
    }
}
