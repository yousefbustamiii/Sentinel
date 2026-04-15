import ArgumentParser
import Foundation

struct StopCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "stop", abstract: "Stop the Sentinel background agent")

    mutating func run() throws {
        guard CommandRateLimitGuard.enforce(.stop) else { return }

        TerminalUI.space()
        
        if !LaunchAgentService.shared.isRunning() {
            TerminalUI.printSingle("Sentinel agent is not currently active.", style: .standard)
            TerminalUI.space()
            return
        }

        // Password gate — must verify before stopping
        guard AuthenticationService.isPasswordSet() else {
            TerminalUI.printSingle("No admin password configured. Run 'sen run' to set one.", style: .error)
            TerminalUI.space()
            return
        }
        
        TerminalUI.printSingle("Admin authentication required to stop Sentinel.", style: .bold)
        TerminalUI.space()
        
        var verified = false
        for attempt in 1...3 {
            guard let input = TerminalUI.readPassword(message: "Admin password:") else { break }
            if AuthenticationService.verifyPassword(input) {
                verified = true
                break
            }
            let remaining = 3 - attempt
            if remaining > 0 {
                TerminalUI.space()
                TerminalUI.printSingle("Incorrect password. \(remaining) attempt(s) remaining.", style: .error)
                TerminalUI.space()
            }
        }
        
        guard verified else {
            TerminalUI.space()
            TerminalUI.printSingle("Authentication failed. Sentinel remains active.", style: .error)
            TerminalUI.space()
            return
        }

        try LaunchAgentService.shared.stop()
        TerminalUI.space()
        TerminalUI.printActionComplete("Sentinel Agent has been successfully stopped.")
        TerminalUI.space()
    }
}
