import Foundation

internal enum TrustPathScope {
    static func matches(_ entry: TrustEntry, queriedPath: String, queriedVolumeUUID: String?) -> Bool {
        let entryPath = normalizedPath(entry.path)

        switch entry.kind {
        case .exactPath, .exactFile, .ecosystem:
            return queriedPath == entryPath
        case .appBundle:
            return matchesBoundary(queriedPath: queriedPath, boundaryPath: entryPath)
        case .removableVolume:
            return matchesRemovableVolume(entry, queriedPath: queriedPath, queriedVolumeUUID: queriedVolumeUUID)
        case .signer, .developer:
            return false
        }
    }

    private static func matchesRemovableVolume(
        _ entry: TrustEntry,
        queriedPath: String,
        queriedVolumeUUID: String?
    ) -> Bool {
        if let entryVolumeUUID = entry.volumeUUID,
           let queriedVolumeUUID,
           entryVolumeUUID == queriedVolumeUUID,
           let queriedVolumeRoot = volumeRootPath(for: queriedPath) {
            return matchesBoundary(queriedPath: queriedPath, boundaryPath: queriedVolumeRoot)
        }

        return matchesBoundary(queriedPath: queriedPath, boundaryPath: normalizedPath(entry.path))
    }

    private static func matchesBoundary(queriedPath: String, boundaryPath: String) -> Bool {
        queriedPath == boundaryPath || queriedPath.hasPrefix(boundaryPath + "/")
    }

    private static func volumeRootPath(for path: String) -> String? {
        let components = URL(fileURLWithPath: path).pathComponents
        guard components.count >= 3, components[1] == "Volumes" else {
            return nil
        }
        return NSString.path(withComponents: Array(components.prefix(3)))
    }

    private static func normalizedPath(_ path: String) -> String {
        URL(fileURLWithPath: path).resolvingSymlinksInPath().path
    }
}
