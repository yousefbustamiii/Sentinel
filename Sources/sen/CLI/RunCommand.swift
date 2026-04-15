import ArgumentParser
import Foundation

struct RunCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "run",
        abstract: "Initialize and activate the Sentinel security service"
    )

    @Flag(name: .shortAndLong, help: "Run in long-lived background mode (foreground)")
    var daemon = false

    @Flag(name: .customLong("trust-ecosystem"), help: "Automatically authorize Homebrew and Nix environments with integrity pinning")
    var trustEcosystem = false

    mutating func run() throws {
        guard CommandRateLimitGuard.enforce(.run) else { return }

        TerminalUI.space()
        TerminalUI.printBanner()
        TerminalUI.space()
        
        if trustEcosystem {
            guard confirmEcosystemTrust() else {
                TerminalUI.space()
                TerminalUI.printSingle("Cancelled ecosystem trust hydration. Running with full detection.", style: .muted)
                TerminalUI.space()
                trustEcosystem = false
                try continueRun()
                TerminalUI.space()
                return
            }

            TerminalUI.printSingle("Hydrating developer ecosystem trust with strict provenance filters...", style: .warning)
            let report = EcosystemManager.hydrate()
            TerminalUI.printSingle("Pinned \(report.addedEntries) ecosystem binaries. Skipped \(report.skippedEntries) candidates.", style: .muted)
            TerminalUI.space()
        }

        try continueRun()
        
        TerminalUI.space()
    }

    private mutating func continueRun() throws {
        // First-run password setup
        if !AuthenticationService.isPasswordSet() {
            TerminalUI.printSingle("First-time setup: create an administrative password.", style: .bold)
            TerminalUI.printSingle("This password will be required to stop or modify Sentinel.", style: .muted)
            TerminalUI.space()
            
            guard let pass1 = TerminalUI.readPassword(message: "Set admin password:") else {
                TerminalUI.space()
                TerminalUI.printSingle("Password setup cancelled. Aborting.", style: .error)
                TerminalUI.space()
                return
            }

            if let validationError = PasswordPolicy.validate(pass1) {
                TerminalUI.space()
                TerminalUI.printSingle("\(validationError) Aborting.", style: .error)
                TerminalUI.space()
                return
            }
            
            guard let pass2 = TerminalUI.readPassword(message: "Confirm admin password:"),
                  pass1 == pass2 else {
                TerminalUI.space()
                TerminalUI.printSingle("Passwords do not match. Aborting.", style: .error)
                TerminalUI.space()
                return
            }
            
            guard AuthenticationService.setup(pass1) else {
                TerminalUI.space()
                TerminalUI.printSingle("Failed to save password to Keychain.", style: .error)
                TerminalUI.space()
                return
            }
            
            TerminalUI.space()
            TerminalUI.printSingle("Password set. Sentinel is now protected.", style: .success)
            TerminalUI.space()
        }
        
        // Dev Mode Resume Check
        if let state = DevModeManager.shared.currentState() {
            TerminalUI.printSingle("Developer Mode is still active.  (\(state.remainingDescription))", style: .warning)
            TerminalUI.space()

            guard let answer = TerminalUI.readInput(prompt: "Would you like to continue in Developer Mode? (y/n)"),
                  answer.lowercased() == "y" || answer.lowercased() == "n" else {
                TerminalUI.space()
                TerminalUI.printSingle("Invalid input. Aborting.", style: .error)
                TerminalUI.space()
                return
            }

            if answer.lowercased() == "n" {
                DevModeManager.shared.disable()
                TerminalUI.space()
                TerminalUI.printSingle("Developer Mode deactivated. Running with full protection.", style: .success)
                TerminalUI.space()
            } else {
                TerminalUI.space()
                TerminalUI.printSingle("Continuing in Developer Mode.", style: .warning)
                TerminalUI.space()
            }
        }

        if daemon {
            startService()
        } else {
            try configureAndLaunch()
        }
    }

    private func confirmEcosystemTrust() -> Bool {
        TerminalUI.printSingle("Ecosystem Trust Warning", style: .warning)
        TerminalUI.printSingle("This feature suppresses detections for selected Homebrew and Nix binaries.", style: .bold)
        TerminalUI.printSingle("It can create false negatives if a developer toolchain is compromised.", style: .error)
        TerminalUI.printSingle("Only resolved executable targets with acceptable ownership and permissions will be pinned.", style: .muted)
        TerminalUI.printSingle("Use this only if you explicitly want reduced scrutiny for your package-manager toolchains.", style: .muted)
        TerminalUI.space()

        guard let answer = TerminalUI.readInput(prompt: "Continue and trust eligible ecosystem binaries? (y/n)") else {
            return false
        }

        return answer.lowercased() == "y"
    }

    private func startService() {
        TerminalUI.printSingle("Starting Sentinel agent...", style: .bold)
        
        LogManager.initialize()
        
        let coordinator = AgentCoordinator()
        coordinator.start()
        
        dispatchMain()
    }

    private func configureAndLaunch() throws {
        TerminalUI.printSingle("Installing Sentinel background service...", style: .bold)
        try LaunchAgentService.shared.installAndStart()
        TerminalUI.space()
        TerminalUI.printActionComplete("Sentinel service started.")
    }
}
