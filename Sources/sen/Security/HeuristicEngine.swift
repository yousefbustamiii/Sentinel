import Foundation

/// Analyzes raw metadata to produce normalized Evidence.
/// These checks do not determine threats; they merely report interesting anomalies.
public struct HeuristicEngine {
    private struct KnownToolRule {
        let identifier: String
        let exactTokens: Set<String>
        let phraseTokens: [String]
    }

    private static let knownToolRules: [KnownToolRule] = [
        KnownToolRule(identifier: "teamviewer", exactTokens: ["teamviewer"], phraseTokens: ["teamviewer"]),
        KnownToolRule(identifier: "anydesk", exactTokens: ["anydesk"], phraseTokens: ["anydesk"]),
        KnownToolRule(identifier: "vnc", exactTokens: ["vnc"], phraseTokens: []),
        KnownToolRule(identifier: "cobalt strike", exactTokens: ["cobalt", "strike"], phraseTokens: ["cobalt strike"]),
        KnownToolRule(identifier: "ngrok", exactTokens: ["ngrok"], phraseTokens: ["ngrok"]),
        KnownToolRule(identifier: "frp", exactTokens: ["frp"], phraseTokens: []),
        KnownToolRule(identifier: "chisel", exactTokens: ["chisel"], phraseTokens: ["chisel"])
    ]

    /// Checks if a name matches known remote access tools or RATs.
    public static func checkNameAnomaly(
        name: String,
        source: ScannerSource,
        context: HeuristicContext = HeuristicContext()
    ) -> Evidence? {
        // Dev Mode: suppress known-tool heuristics entirely.
        if DevModeManager.shared.isActive() {
            LogManager.record(LogEntry(
                eventName: "devmode.suppressed",
                toolName: "HeuristicEngine",
                severity: .debug,
                message: "Suppressed knownToolMatch check for \(name)",
                category: "devmode"
            ))
            return nil
        }

        guard let match = matchedKnownTool(in: name) else { return nil }

        let shouldReport = context.hasHighConfidenceCorroboration ||
            (!context.looksOperationallyBenign && context.isFirstSeenRecently)

        guard shouldReport else {
            return nil
        }

        let basis = nameEvidenceBasis(context: context)
        return Evidence(
            code: .knownToolMatch,
            description: "Low-confidence tool-name match for \(match.identifier), corroborated by \(basis).",
            source: source,
            context: match.identifier
        )
    }

    /// Checks for execution from non-standard or temporary locations.
    public static func checkPathAnomaly(
        path: String,
        source: ScannerSource,
        context: HeuristicContext = HeuristicContext()
    ) -> Evidence? {
        let lower = path.lowercased()
        let home   = NSHomeDirectory().lowercased()

        // Dev Mode: exempt ~/Projects from path anomaly checks.
        if DevModeManager.shared.isActive(),
           lower.hasPrefix(home + "/projects/") || lower == home + "/projects" {
            LogManager.record(LogEntry(
                eventName: "devmode.suppressed",
                toolName: "HeuristicEngine",
                severity: .debug,
                message: "Suppressed pathAnomaly check for \(path)",
                category: "devmode"
            ))
            return nil
        }

        if (lower.contains("/tmp/") || lower.contains("/var/tmp/")) &&
            !(context.isKnownDeveloperTemporaryPath && context.looksOperationallyBenign) {
            return Evidence(
                code: .pathAnomaly,
                description: "Execution from a volatile temporary location outside normal install roots.",
                source: source,
                context: path
            )
        }

        if lower.hasPrefix(home + "/.") && !context.isKnownDeveloperHiddenPath {
            return Evidence(
                code: .hiddenRootItem,
                description: "Executable is located in a hidden user directory outside common developer config paths.",
                source: source,
                context: path
            )
        }
        return nil
    }

    /// Checks for execution from user-writable search-path locations.
    public static func checkSearchPathAnomaly(
        path: String,
        source: ScannerSource,
        context: HeuristicContext = HeuristicContext()
    ) -> Evidence? {
        guard context.isUserWritableSearchPathExecution else { return nil }
        guard !context.looksOperationallyBenign || !context.isRecurringProcessSighting else { return nil }

        return Evidence(
            code: .searchPathExecution,
            description: "Execution from a user-writable search-path location without stable benign context.",
            source: source,
            context: path
        )
    }

    /// Checks for suspicious parent or grandparent execution ancestry.
    public static func checkParentAnomaly(
        source: ScannerSource,
        context: HeuristicContext = HeuristicContext()
    ) -> Evidence? {
        guard context.hasSuspiciousAncestry else { return nil }

        let lineage = [context.parentProcessName, context.grandparentProcessName]
            .compactMap { $0 }
            .joined(separator: " <- ")

        return Evidence(
            code: .suspiciousParent,
            description: "Process launched through an unusual parent chain lacking normal interactive context.",
            source: source,
            context: lineage.isEmpty ? nil : lineage
        )
    }

    /// Checks for network ports typically associated with backdoors.
    public static func checkPortAnomaly(
        _ lsofLine: String,
        source: ScannerSource,
        context: HeuristicContext = HeuristicContext()
    ) -> Evidence? {
        let backdoorPorts = ["4444", "1337", "31337"]
        guard let match = backdoorPorts.first(where: { lsofLine.contains(":\($0)") }) else { return nil }

        if context.isLocalOnlyListener && context.looksOperationallyBenign {
            return nil
        }

        if !context.hasResolvedExecutablePath && context.isLocalOnlyListener && context.isSignatureValid {
            return nil
        }

        if context.isRecurringListener && context.isLocalOnlyListener && context.isSignatureValid {
            return nil
        }

        let corroborated = context.hasPersistence ||
            !context.isSignatureValid ||
            (!context.isLocalOnlyListener && context.hasResolvedExecutablePath) ||
            context.hasSuspiciousPathLocation ||
            matchedKnownTool(in: context.processName ?? "") != nil

        guard corroborated else { return nil }

        return Evidence(
            code: .anomalousPort,
            description: "Listening on port \(match) with additional execution-context risk factors.",
            source: source,
            context: match
        )
    }

    private static func matchedKnownTool(in name: String) -> KnownToolRule? {
        let normalized = normalize(name)
        let tokenSet = Set(normalized.split(separator: " ").map(String.init))

        return knownToolRules.first { rule in
            if rule.phraseTokens.contains(where: { normalized.contains($0) }) {
                return true
            }

            return !rule.exactTokens.isDisjoint(with: tokenSet)
        }
    }

    private static func normalize(_ name: String) -> String {
        name.lowercased()
            .map { $0.isLetter || $0.isNumber ? $0 : " " }
            .reduce(into: "") { partialResult, character in
                partialResult.append(character)
            }
            .split(separator: " ", omittingEmptySubsequences: true)
            .joined(separator: " ")
    }

    private static func nameEvidenceBasis(context: HeuristicContext) -> String {
        if context.hasPersistence {
            return "persistence linkage"
        }
        if context.listenerPort != nil {
            return "network-listener behavior"
        }
        if !context.isSignatureValid {
            return "an unverified signer"
        }
        if context.hasSuspiciousPathLocation {
            return "a suspicious execution path"
        }
        if context.parentProcessName != nil {
            return "recent or non-benign execution context"
        }
        return "recent execution context"
    }
}
