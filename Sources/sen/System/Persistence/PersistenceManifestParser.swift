import Foundation

enum PersistenceManifestParser {
    static func snapshot(for plistURL: URL) -> PersistenceManifestSnapshot? {
        let normalizedURL = plistURL.resolvingSymlinksInPath()
        guard normalizedURL.pathExtension.lowercased() == "plist" else { return nil }

        let fileManager = FileManager.default
        let attributes = try? fileManager.attributesOfItem(atPath: normalizedURL.path)
        let lastModified = attributes?[.modificationDate] as? Date
        let fileHash = FileHasher.sha512(at: normalizedURL)

        guard let data = try? Data(contentsOf: normalizedURL) else {
            return PersistenceManifestSnapshot(
                path: normalizedURL.path,
                fileHash: fileHash,
                targetPath: nil,
                signerTeamID: nil,
                lastModified: lastModified,
                isValidPropertyList: false,
                parseError: "Unable to read persistence manifest"
            )
        }

        guard let dict = try? PropertyListSerialization.propertyList(from: data, options: [], format: nil) as? [String: Any] else {
            return PersistenceManifestSnapshot(
                path: normalizedURL.path,
                fileHash: fileHash,
                targetPath: nil,
                signerTeamID: nil,
                lastModified: lastModified,
                isValidPropertyList: false,
                parseError: "Persistence manifest is not a valid property list"
            )
        }

        let targetPath = ((dict["Program"] as? String) ?? (dict["ProgramArguments"] as? [String])?.first)
            .map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path }
        let signerTeamID = targetPath.flatMap {
            CodeSignatureService.getIdentity(for: URL(fileURLWithPath: $0)).teamID
        }

        return PersistenceManifestSnapshot(
            path: normalizedURL.path,
            fileHash: fileHash,
            targetPath: targetPath,
            signerTeamID: signerTeamID,
            lastModified: lastModified,
            isValidPropertyList: true,
            parseError: nil
        )
    }
}
