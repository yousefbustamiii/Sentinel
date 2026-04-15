import Foundation

public struct HeuristicContext {
    public let path: String?
    public let processName: String?
    public let parentProcessName: String?
    public let grandparentProcessName: String?
    public let signerTeamID: String?
    public let bundleID: String?
    public let isAppleSigned: Bool
    public let isSignatureValid: Bool
    public let isInteractive: Bool
    public let hasPersistence: Bool
    public let firstSeenAt: Date?
    public let listenerPort: Int?
    public let userID: Int?
    public let userName: String?
    public let isLocalOnlyListener: Bool
    public let hasResolvedExecutablePath: Bool
    public let isRecurringListener: Bool
    public let existingSightingCount: Int

    public init(
        path: String? = nil,
        processName: String? = nil,
        parentProcessName: String? = nil,
        grandparentProcessName: String? = nil,
        signerTeamID: String? = nil,
        bundleID: String? = nil,
        isAppleSigned: Bool = false,
        isSignatureValid: Bool = false,
        isInteractive: Bool = false,
        hasPersistence: Bool = false,
        firstSeenAt: Date? = nil,
        listenerPort: Int? = nil,
        userID: Int? = nil,
        userName: String? = nil,
        isLocalOnlyListener: Bool = false,
        hasResolvedExecutablePath: Bool = false,
        isRecurringListener: Bool = false,
        existingSightingCount: Int = 0
    ) {
        self.path = path
        self.processName = processName
        self.parentProcessName = parentProcessName
        self.grandparentProcessName = grandparentProcessName
        self.signerTeamID = signerTeamID
        self.bundleID = bundleID
        self.isAppleSigned = isAppleSigned
        self.isSignatureValid = isSignatureValid
        self.isInteractive = isInteractive
        self.hasPersistence = hasPersistence
        self.firstSeenAt = firstSeenAt
        self.listenerPort = listenerPort
        self.userID = userID
        self.userName = userName
        self.isLocalOnlyListener = isLocalOnlyListener
        self.hasResolvedExecutablePath = hasResolvedExecutablePath
        self.isRecurringListener = isRecurringListener
        self.existingSightingCount = existingSightingCount
    }
}

internal extension HeuristicContext {
    static let empty = HeuristicContext()

    var normalizedPath: String? {
        path.map { URL(fileURLWithPath: $0).resolvingSymlinksInPath().path.lowercased() }
    }

    var isFirstSeenRecently: Bool {
        guard let firstSeenAt else { return true }
        return Date().timeIntervalSince(firstSeenAt) < 24 * 60 * 60
    }

    var isRecurringProcessSighting: Bool {
        existingSightingCount >= 3 || !isFirstSeenRecently
    }

    var isKnownDeveloperHiddenPath: Bool {
        guard let path = normalizedPath else { return false }
        let home = NSHomeDirectory().lowercased()
        let allowlistedPrefixes = [
            home + "/.nix-profile/",
            home + "/.cache/",
            home + "/.config/",
            home + "/.local/",
            home + "/.cargo/",
            home + "/.rustup/",
            home + "/.npm/",
            home + "/.pnpm/",
            home + "/.yarn/",
            home + "/.bun/",
            home + "/.swiftpm/",
            home + "/.vscode/",
            home + "/.cursor/",
            home + "/.orbstack/",
            home + "/.docker/",
            home + "/.kube/",
            home + "/.terraform.d/"
        ]
        return allowlistedPrefixes.contains(where: { path.hasPrefix($0) })
    }

    var isKnownDeveloperTemporaryPath: Bool {
        guard let path = normalizedPath else { return false }

        let tempMarkers = [
            "/private/var/folders/",
            "/tmp/swift-",
            "/tmp/temporarydirectory.",
            "/tmp/go-build",
            "/tmp/nix-build-",
            "/tmp/yarn--",
            "/tmp/pnpm-",
            "/tmp/uv-",
            "/var/folders/"
        ]

        return tempMarkers.contains(where: { path.contains($0) })
    }

    var isKnownStableInstallPath: Bool {
        guard let path = normalizedPath else { return false }

        let home = NSHomeDirectory().lowercased()
        let stablePrefixes = [
            "/applications/",
            "/system/applications/",
            "/library/",
            "/opt/homebrew/",
            "/usr/local/",
            "/nix/store/",
            home + "/applications/",
            home + "/.nix-profile/"
        ]

        return stablePrefixes.contains(where: { path.hasPrefix($0) }) || isKnownDeveloperHiddenPath
    }

    var hasSuspiciousPathLocation: Bool {
        guard let path = normalizedPath else { return false }
        let home = NSHomeDirectory().lowercased()

        let isTemp = path.contains("/tmp/") || path.contains("/var/tmp/")
        if isTemp && !isKnownDeveloperTemporaryPath {
            return true
        }

        let isHiddenHomePath = path.hasPrefix(home + "/.")
        return isHiddenHomePath && !isKnownDeveloperHiddenPath
    }

    var isUserWritableSearchPathExecution: Bool {
        guard let path = normalizedPath else { return false }

        let allowlistedPrefixes = [
            NSHomeDirectory().lowercased() + "/bin/",
            NSHomeDirectory().lowercased() + "/.local/bin/",
            NSHomeDirectory().lowercased() + "/.cargo/bin/",
            NSHomeDirectory().lowercased() + "/.npm/",
            NSHomeDirectory().lowercased() + "/.pnpm/",
            NSHomeDirectory().lowercased() + "/.yarn/",
            NSHomeDirectory().lowercased() + "/.bun/bin/"
        ]

        guard allowlistedPrefixes.contains(where: { path.hasPrefix($0) }) else {
            return false
        }

        return FileManager.default.isWritableFile(atPath: path)
    }

    var parentSuggestsUserInitiatedExecution: Bool {
        guard let parentProcessName else { return false }
        let parent = parentProcessName.lowercased()
        let knownInteractiveParents = [
            "terminal",
            "iterm2",
            "warp",
            "ghostty",
            "xcode",
            "cursor",
            "code",
            "sublime text"
        ]
        return knownInteractiveParents.contains(where: { parent.contains($0) })
    }

    var hasSuspiciousAncestry: Bool {
        let lineage = [parentProcessName, grandparentProcessName]
            .compactMap { $0?.lowercased() }

        guard !lineage.isEmpty else { return false }

        let suspiciousAncestors = [
            "launchd",
            "xpcproxy",
            "osascript",
            "bash",
            "sh",
            "zsh",
            "python",
            "python3",
            "perl",
            "ruby",
            "curl",
            "wget"
        ]

        guard lineage.contains(where: { ancestor in
            suspiciousAncestors.contains(where: { ancestor.contains($0) })
        }) else {
            return false
        }

        return !isInteractive &&
            (hasSuspiciousPathLocation || !isSignatureValid || isFirstSeenRecently) &&
            !parentSuggestsUserInitiatedExecution
    }

    var hasHighConfidenceCorroboration: Bool {
        hasPersistence || (!isLocalOnlyListener && listenerPort != nil) || !isSignatureValid || hasSuspiciousPathLocation
    }

    var looksOperationallyBenign: Bool {
        isSignatureValid &&
        (isInteractive || parentSuggestsUserInitiatedExecution) &&
        isKnownStableInstallPath &&
        !hasPersistence &&
        (listenerPort == nil || isLocalOnlyListener) &&
        !isRecurringListener
    }

    var hasWeakNetworkContext: Bool {
        listenerPort != nil && (isLocalOnlyListener || !hasResolvedExecutablePath || isRecurringListener)
    }
}
