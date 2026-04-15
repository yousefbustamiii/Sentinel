import Foundation

enum USBContentRules {
    static let bundleExtensions: Set<String> = ["app", "pkg", "dmg"]
    static let scriptExtensions: Set<String> = ["sh", "command", "zsh", "bash"]

    private static let benignHiddenRootArtifacts: Set<String> = [
        ".trashes",
        ".spotlight-v100",
        ".fseventsd",
        ".ds_store"
    ]

    private static let suspiciousNameTokens: Set<String> = [
        "payload",
        "dropper",
        "inject",
        "keylog",
        "exploit"
    ]

    private static let suspiciousMultiPartTokens: [[String]] = [
        ["stage", "1"],
        ["stage", "2"],
        ["stage", "loader"]
    ]

    private static let benignInstallerHints: [String] = [
        "install",
        "installer",
        "setup",
        "firmware",
        "update",
        "upgrade",
        "driver",
        "utility",
        "project",
        "school"
    ]

    static func shouldIgnoreHiddenRootArtifact(_ item: USBRootItemSnapshot) -> Bool {
        benignHiddenRootArtifacts.contains(item.lowercasedName)
    }

    static func isContextuallySuspiciousFilename(_ item: USBRootItemSnapshot) -> Bool {
        guard item.isExecutableLikeAtRoot else { return false }
        guard !looksBenignInstallerLike(item) else { return false }

        let normalizedTokens = normalizedTokens(for: item.lowercasedName)
        let tokenSet = Set(normalizedTokens)

        if !suspiciousNameTokens.isDisjoint(with: tokenSet) {
            return true
        }

        return suspiciousMultiPartTokens.contains { Set($0).isSubset(of: tokenSet) }
    }

    static func shouldFlagExecutableAtRoot(_ item: USBRootItemSnapshot) -> Bool {
        guard item.isExecutableLikeAtRoot else { return false }

        if item.isScriptAtRoot {
            return true
        }

        return !looksBenignInstallerLike(item) || isContextuallySuspiciousFilename(item)
    }

    private static func looksBenignInstallerLike(_ item: USBRootItemSnapshot) -> Bool {
        benignInstallerHints.contains(where: { item.lowercasedName.contains($0) })
    }

    private static func normalizedTokens(for name: String) -> [String] {
        name
            .map { $0.isLetter || $0.isNumber ? $0 : " " }
            .reduce(into: "") { result, character in result.append(character) }
            .split(separator: " ")
            .map(String.init)
    }
}
