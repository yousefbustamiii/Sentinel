import ArgumentParser
import Foundation

struct PasswordCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "password",
        abstract: "Change the Sentinel administrative password"
    )

    mutating func run() throws {
        guard CommandRateLimitGuard.enforce(.passwordChange) else { return }

        TerminalUI.space()

        guard AuthenticationService.isPasswordSet() else {
            TerminalUI.printSingle("No admin password configured. Run 'sen run' first.", style: .error)
            TerminalUI.space()
            return
        }

        // Step 1: Verify current password
        TerminalUI.printSingle("Change Administrative Password", style: .bold)
        TerminalUI.printSeparator()
        TerminalUI.space()

        guard let current = TerminalUI.readPassword(message: "Current password:") else {
            TerminalUI.space()
            return
        }

        guard AuthenticationService.verifyPassword(current) else {
            TerminalUI.space()
            TerminalUI.printSingle("Incorrect password. No changes made.", style: .error)
            TerminalUI.space()
            return
        }

        TerminalUI.space()

        // Step 2: Collect and confirm new password
        guard let newPass = TerminalUI.readPassword(message: "New password:") else {
            TerminalUI.space()
            TerminalUI.printSingle("Password change cancelled. No changes made.", style: .error)
            TerminalUI.space()
            return
        }

        if let validationError = PasswordPolicy.validate(newPass) {
            TerminalUI.space()
            TerminalUI.printSingle("\(validationError) No changes made.", style: .error)
            TerminalUI.space()
            return
        }

        guard let confirm = TerminalUI.readPassword(message: "Confirm new password:"),
              newPass == confirm else {
            TerminalUI.space()
            TerminalUI.printSingle("Passwords do not match. No changes made.", style: .error)
            TerminalUI.space()
            return
        }

        // Step 3: Atomic keychain update
        guard AuthenticationService.setup(newPass) else {
            TerminalUI.space()
            TerminalUI.printSingle("Failed to update Keychain. No changes made.", style: .error)
            TerminalUI.space()
            return
        }

        LogManager.initialize()
        LogManager.record(LogEntry(
            eventName: "admin.password.changed",
            toolName: "",
            severity: .info,
            message: ""
        ))

        TerminalUI.space()
        TerminalUI.printActionComplete("Password updated successfully.")
        TerminalUI.space()
    }
}
