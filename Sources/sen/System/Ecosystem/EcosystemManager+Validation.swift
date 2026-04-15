import Darwin
import Foundation

extension EcosystemManager {
    internal static func verifyHomebrewIntegrity(root: URL) -> Bool {
        let etc = root.appending(path: "etc")
        let varDir = root.appending(path: "var")
        let brewTool = root.appending(path: "bin").appending(path: "brew")

        return FileManager.default.fileExists(atPath: etc.path) &&
               FileManager.default.fileExists(atPath: varDir.path) &&
               FileManager.default.fileExists(atPath: brewTool.path) &&
               !isWritableByOthers(brewTool) &&
               !hasSuspiciousOwnership(at: brewTool)
    }

    static func candidateEntry(
        for fileURL: URL,
        provenance: Provenance,
        allowedPrefixes: [String]
    ) -> Candidate? {
        let resolvedURL = fileURL.resolvingSymlinksInPath()
        let resolvedPath = resolvedURL.path

        guard allowedPrefixes.contains(where: { resolvedPath.hasPrefix($0) }) else {
            return nil
        }

        let fileManager = FileManager.default
        guard fileManager.fileExists(atPath: resolvedPath),
              isRegularExecutableFile(resolvedURL),
              !isWritableByOthers(resolvedURL),
              !hasSuspiciousOwnership(at: resolvedURL),
              let fingerprint = FileHasher.sha512(at: resolvedURL)
        else {
            return nil
        }

        let identity = CodeSignatureService.getIdentity(for: resolvedURL)
        if identity.isAppleSigned { return nil }

        let attributes = try? fileManager.attributesOfItem(atPath: resolvedPath)
        let ownerUserID = attributes?[.ownerAccountID] as? Int ?? -1
        let ownerGroupID = attributes?[.groupOwnerAccountID] as? Int ?? -1
        let fileType = (attributes?[.type] as? FileAttributeType)?.rawValue ?? "unknown"

        return Candidate(
            path: resolvedPath,
            fingerprint: fingerprint,
            bundleID: identity.bundleID,
            teamID: identity.teamID,
            provenance: provenance.rawValue,
            fileType: fileType,
            ownerUserID: ownerUserID,
            ownerGroupID: ownerGroupID
        )
    }

    static func isRegularExecutableFile(_ url: URL) -> Bool {
        let path = url.path
        guard FileManager.default.isExecutableFile(atPath: path) else { return false }
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: path),
              let fileType = attributes[.type] as? FileAttributeType else {
            return false
        }
        return fileType == .typeRegular
    }

    static func isWritableByOthers(_ url: URL) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let permissions = attributes[.posixPermissions] as? NSNumber else {
            return true
        }

        let mode = permissions.uint16Value
        return (mode & 0o002) != 0 || (mode & 0o020) != 0
    }

    static func hasSuspiciousOwnership(at url: URL) -> Bool {
        guard let attributes = try? FileManager.default.attributesOfItem(atPath: url.path),
              let ownerUserID = attributes[.ownerAccountID] as? Int else {
            return true
        }

        let currentUserID = Int(getuid())
        return ownerUserID != 0 && ownerUserID != currentUserID
    }
}
