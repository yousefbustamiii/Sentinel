import ArgumentParser
import Foundation

struct TrustCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "trust",
        abstract: "Manage administrative trust for system paths"
    )

    mutating func run() throws {
        guard CommandRateLimitGuard.enforce(.trust) else { return }

        TerminalUI.space()
        
        TrustManager.shared.initialize()

        TerminalUI.printSingle("Sentinel Trust Management", style: .bold)
        TerminalUI.printSeparator()
        TerminalUI.space()

        TerminalUI.printMenu(options: [
            "Authorize Path",
            "View Trusted Paths",
            "Revoke Authorization"
        ])
        
        TerminalUI.space()
        guard let input = TerminalUI.readInput(prompt: "Select (1-3) or 'q' to exit") else { 
            TerminalUI.space()
            return 
        }
        
        if input.lowercased() == "q" { 
            TerminalUI.space()
            return 
        }

        switch input {
        case "1": addTrust()
        case "2": viewTrusts()
        case "3": revokeTrust()
        default:  break
        }
        
        TerminalUI.space()
    }

    private func addTrust() {
        TerminalUI.space()
        guard let cleaned = TerminalUI.readInput(prompt: "Enter path (file, app, or volume) to authorize")?
            .replacingOccurrences(of: "\"", with: "")
            .replacingOccurrences(of: "'", with: ""), !cleaned.isEmpty else { return }

        switch TrustValidator.validate(cleaned) {
        case .failure(let error):
            TerminalUI.printSingle(error.description, style: .error)
        case .success(let url):
            let path = url.path
            let identity = url.codeIdentity
            let kind = resolveKind(at: url, identity: identity)
            guard confirmSelectionIfNeeded(kind: kind, path: path, identity: identity) else { return }
            let integrity = TrustIntegritySnapshotResolver.make(for: url, kind: kind)
            
            let entry = TrustEntry(
                kind: kind,
                path: path,
                fingerprint: integrity.fingerprint,
                volumeUUID: url.volumeUUID,
                bundleID: identity.bundleID,
                teamID: identity.teamID,
                resolvedPath: integrity.resolvedPath,
                fileType: integrity.fileType,
                updatePolicy: kind == .appBundle ? .allowSignedUpdates : .strict
            )

            if TrustManager.shared.authorize(entry) {
                TerminalUI.space()
                TerminalUI.printSingle("Authorization established for \(kind.displayName):", style: .success)
                TerminalUI.printSingle("   Path:   \(path)")
                if let team = identity.teamID { TerminalUI.printSingle("   Signer: \(team)") }
                if let bID  = identity.bundleID { TerminalUI.printSingle("   Bundle: \(bID)") }
            }
        }
    }

    private func viewTrusts() {
        TerminalUI.space()
        let entries = TrustManager.shared.entries
        if entries.isEmpty {
            TerminalUI.printSingle("No trusted paths configured.", style: .standard)
            return
        }

        TerminalUI.printSingle("Currently Trusted Paths", style: .bold)
        TerminalUI.printSeparator()

        for (i, entry) in entries.enumerated() {
            let status = TrustManager.shared.checkStatus(path: entry.path)
            let indicator = status == .tampered ? TerminalUI.tamperedIndicator : "[\(entry.kind.displayName)]"
            
            TerminalUI.printSingle("\(i + 1). \(entry.path) \(indicator)")
            if let team = entry.teamID { TerminalUI.printSingle("   Signer: \(team)") }
            if let hash = entry.fingerprint { TerminalUI.printSingle("   Hash:   \(hash.prefix(12))...") }
        }
    }

    private func revokeTrust() {
        TerminalUI.space()
        let entries = TrustManager.shared.entries
        if entries.isEmpty {
            TerminalUI.printSingle("Trust store is empty.", style: .muted)
            return
        }

        TerminalUI.printMenu(options: entries.map { $0.path })
        TerminalUI.space()
        
        if let input = TerminalUI.readInput(prompt: "Select index to revoke"), 
           let idx = Int(input), idx >= 1, idx <= entries.count {
            _ = TrustManager.shared.revoke(at: idx - 1)
            TerminalUI.space()
            TerminalUI.printSingle("Authorization revoked.", style: .success)
        }
    }

    private func resolveKind(at url: URL, identity: CodeSignatureService.Identity) -> TrustKind {
        if url.path.starts(with: "/Volumes/") { return .removableVolume }

        let supportsSignerScope = identity.teamID != nil
        if url.path.hasSuffix(".app") {
            return selectTrustKind(
                options: supportsSignerScope ? [.appBundle, .exactPath, .signer] : [.appBundle, .exactPath],
                prompt: "Select trust scope for this app"
            ) ?? .appBundle
        }

        if supportsSignerScope {
            return selectTrustKind(
                options: [.exactPath, .signer],
                prompt: "Select trust scope for this binary"
            ) ?? .exactPath
        }

        return .exactPath
    }

    private func selectTrustKind(options: [TrustKind], prompt: String) -> TrustKind? {
        TerminalUI.space()
        TerminalUI.printMenu(options: options.enumerated().map { _, kind in kind.displayName })
        TerminalUI.space()

        guard let input = TerminalUI.readInput(prompt: "\(prompt) (1-\(options.count))"),
              let idx = Int(input),
              idx >= 1,
              idx <= options.count
        else {
            return nil
        }

        return options[idx - 1]
    }

    private func confirmSelectionIfNeeded(
        kind: TrustKind,
        path: String,
        identity: CodeSignatureService.Identity
    ) -> Bool {
        guard kind == .signer else { return true }

        TerminalUI.space()
        TerminalUI.printSingle("Signer trust is broad and high-impact.", style: .warning)
        TerminalUI.printSingle("This trusts future binaries signed by the same developer, not just this path.", style: .error)
        if let teamID = identity.teamID {
            TerminalUI.printSingle("Signer Team ID: \(teamID)", style: .muted)
        }
        TerminalUI.printSingle("Selected path: \(path)", style: .muted)
        TerminalUI.space()

        guard let confirmation = TerminalUI.readInput(prompt: "Type SIGNER to confirm broad signer trust") else {
            return false
        }

        if confirmation == "SIGNER" {
            return true
        }

        TerminalUI.space()
        TerminalUI.printSingle("Signer trust cancelled. No changes made.", style: .muted)
        return false
    }
}
