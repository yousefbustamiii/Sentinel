import ArgumentParser
import Foundation

struct DevCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "dev",
        abstract: "Toggle Sentinel Developer Mode — suppresses heuristics for local development"
    )

    mutating func run() throws {
        guard CommandRateLimitGuard.enforce(.dev) else { return }

        TerminalUI.space()

        // Dev mode is currently active — show a status dashboard with options.
        if let state = DevModeManager.shared.currentState() {
            TerminalUI.printSingle("Developer Mode", style: .bold)
            TerminalUI.printSeparator()
            TerminalUI.space()
            TerminalUI.printSingle("Status:    Active ⚠", style: .warning)
            TerminalUI.printSingle("Duration:  \(state.remainingDescription)", style: .muted)
            TerminalUI.space()
            TerminalUI.printSingle("Suppressed protections:", style: .muted)
            TerminalUI.printSingle("  • Path anomaly detection for ~/Projects", style: .muted)
            TerminalUI.printSingle("  • Known tool name heuristics", style: .muted)
            TerminalUI.printSingle("  • USB volume scanning", style: .muted)
            TerminalUI.printSingle("  • Signature checks for Team ID signed binaries", style: .muted)
            TerminalUI.space()
            TerminalUI.printMenu(options: [
                "Keep Developer Mode active",
                "Deactivate Developer Mode — restore full protection"
            ])

            guard let choice = TerminalUI.readInput(prompt: "Select (1-2) or 'q' to cancel"),
                  !choice.isEmpty, choice.lowercased() != "q" else {
                TerminalUI.space()
                return
            }

            switch choice {
            case "1":
                TerminalUI.space()
                TerminalUI.printSingle("Developer Mode remains active.", style: .warning)

            case "2":
                DevModeManager.shared.disable()
                TerminalUI.space()
                TerminalUI.printActionComplete("Developer Mode deactivated. Full protection restored.")

            default:
                TerminalUI.space()
                TerminalUI.printSingle("Invalid selection. No changes made.", style: .error)
            }

            TerminalUI.space()
            return
        }

        // Activation flow
        TerminalUI.printSingle("⚠  Developer Mode Warning", style: .warning)
        TerminalUI.printSeparator()
        TerminalUI.space()
        TerminalUI.printSingle("You are about to switch Sentinel into Developer Mode.", style: .bold)
        TerminalUI.space()
        TerminalUI.printSingle("The following protections will be suppressed:", style: .muted)
        TerminalUI.printSingle("  • Path anomaly detection for ~/Projects", style: .muted)
        TerminalUI.printSingle("  • Known tool name heuristics", style: .muted)
        TerminalUI.printSingle("  • USB volume scanning", style: .muted)
        TerminalUI.printSingle("  • Signature checks for your Team ID signed binaries", style: .muted)
        TerminalUI.space()
        TerminalUI.printSingle("This significantly reduces Sentinel's threat detection capability.", style: .error)
        TerminalUI.space()

        // Duration selection
        TerminalUI.printSingle("How long would you like to enable Developer Mode?", style: .bold)
        TerminalUI.space()
        TerminalUI.printMenu(options: [
            "Time-limited  (1–7 days)",
            "Unlimited  — active until manually deactivated"
        ])

        guard let choice = TerminalUI.readInput(prompt: "Select (1-2) or 'q' to cancel"),
              !choice.isEmpty, choice.lowercased() != "q" else {
            TerminalUI.space()
            TerminalUI.printSingle("Cancelled. No changes made.", style: .muted)
            TerminalUI.space()
            return
        }

        let duration: DevModeState.Duration

        switch choice {
        case "1":
            TerminalUI.space()
            guard let dayInput = TerminalUI.readInput(prompt: "Enter duration in days (1–7):"),
                  let days = Int(dayInput), days >= 1, days <= 7 else {
                TerminalUI.space()
                TerminalUI.printSingle("Invalid duration. Must be between 1 and 7 days.", style: .error)
                TerminalUI.space()
                return
            }
            let expiry = Date().addingTimeInterval(TimeInterval(days * 86_400))
            duration = .timed(until: expiry)

        case "2":
            duration = .unlimited

        default:
            TerminalUI.space()
            TerminalUI.printSingle("Invalid selection. No changes made.", style: .error)
            TerminalUI.space()
            return
        }

        TerminalUI.space()

        // Final confirmation
        let durationLabel: String
        if case .timed(let exp) = duration {
            let days = Int(ceil(exp.timeIntervalSince(Date()) / 86_400))
            durationLabel = "\(days) day\(days == 1 ? "" : "s")"
        } else {
            durationLabel = "unlimited duration"
        }

        TerminalUI.printSingle("Developer Mode will be active for \(durationLabel).", style: .bold)
        TerminalUI.space()

        guard let confirm = TerminalUI.readInput(prompt: "Activate Developer Mode? (y/n)"),
              confirm.lowercased() == "y" else {
            TerminalUI.space()
            TerminalUI.printSingle("Cancelled. No changes made.", style: .muted)
            TerminalUI.space()
            return
        }

        guard verifyAdministrativePasswordForActivation() else { return }

        DevModeManager.shared.enable(duration: duration)
        TerminalUI.space()
        TerminalUI.printActionComplete("Developer Mode activated.")
        TerminalUI.space()
    }

    private func verifyAdministrativePasswordForActivation() -> Bool {
        guard AuthenticationService.isPasswordSet() else {
            TerminalUI.space()
            TerminalUI.printSingle("No admin password configured. Run 'sen run' to set one before enabling Developer Mode.", style: .error)
            TerminalUI.space()
            return false
        }

        TerminalUI.space()
        TerminalUI.printSingle("Administrative authentication required to enable Developer Mode.", style: .bold)
        TerminalUI.space()

        for attempt in 1...3 {
            guard let input = TerminalUI.readPassword(message: "Admin password:") else { break }
            if AuthenticationService.verifyPassword(input) {
                return true
            }

            let remaining = 3 - attempt
            if remaining > 0 {
                TerminalUI.space()
                TerminalUI.printSingle("Incorrect password. \(remaining) attempt(s) remaining.", style: .error)
                TerminalUI.space()
            }
        }

        TerminalUI.space()
        TerminalUI.printSingle("Authentication failed. Developer Mode remains disabled.", style: .error)
        TerminalUI.space()
        return false
    }
}
