import Foundation

internal struct TrustIntegritySnapshot {
    let fingerprint: String?
    let resolvedPath: String?
    let fileType: String?
}

internal enum TrustIntegritySnapshotResolver {
    static func make(for url: URL, kind: TrustKind) -> TrustIntegritySnapshot {
        switch kind {
        case .appBundle:
            return makeBundleSnapshot(for: url)
        default:
            return makeFileSnapshot(for: url)
        }
    }

    static func currentFingerprint(for entry: TrustEntry) -> String? {
        let baseURL = URL(fileURLWithPath: entry.path)

        switch entry.kind {
        case .appBundle:
            if let resolvedPath = entry.resolvedPath {
                let resolvedURL = URL(fileURLWithPath: resolvedPath)
                if FileManager.default.fileExists(atPath: resolvedURL.path) {
                    return FileHasher.sha512(at: resolvedURL)
                }
            }
            return makeBundleSnapshot(for: baseURL).fingerprint
        default:
            return FileHasher.sha512(at: baseURL)
        }
    }

    private static func makeFileSnapshot(for url: URL) -> TrustIntegritySnapshot {
        let resolvedURL = url.resolvingSymlinksInPath()
        let fileType = fileType(at: resolvedURL)
        return TrustIntegritySnapshot(
            fingerprint: FileHasher.sha512(at: resolvedURL),
            resolvedPath: resolvedURL.path,
            fileType: fileType
        )
    }

    private static func makeBundleSnapshot(for bundleURL: URL) -> TrustIntegritySnapshot {
        guard let executableURL = bundleExecutableURL(for: bundleURL) else {
            return TrustIntegritySnapshot(
                fingerprint: nil,
                resolvedPath: nil,
                fileType: "bundleExecutableMissing"
            )
        }

        let resolvedExecutableURL = executableURL.resolvingSymlinksInPath()
        return TrustIntegritySnapshot(
            fingerprint: FileHasher.sha512(at: resolvedExecutableURL),
            resolvedPath: resolvedExecutableURL.path,
            fileType: "bundleExecutable"
        )
    }

    private static func bundleExecutableURL(for bundleURL: URL) -> URL? {
        if let bundle = Bundle(url: bundleURL), let executableURL = bundle.executableURL {
            return executableURL
        }

        let infoPlistURL = bundleURL.appending(path: "Contents").appending(path: "Info.plist")
        guard
            let data = try? Data(contentsOf: infoPlistURL),
            let plist = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any],
            let executableName = plist["CFBundleExecutable"] as? String,
            !executableName.isEmpty
        else {
            return nil
        }

        return bundleURL.appending(path: "Contents").appending(path: "MacOS").appending(path: executableName)
    }

    private static func fileType(at url: URL) -> String {
        let attributes = try? FileManager.default.attributesOfItem(atPath: url.path)
        return (attributes?[.type] as? FileAttributeType)?.rawValue ?? "unknown"
    }
}
