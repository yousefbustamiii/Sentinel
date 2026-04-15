import ArgumentParser
import Foundation

struct StatusCommand: ParsableCommand {
    static let configuration = CommandConfiguration(commandName: "status", abstract: "Show current Sentinel status")

    mutating func run() throws {
        guard CommandRateLimitGuard.enforce(.status) else { return }

        TerminalUI.space()

        let snapshot = StatusSnapshot.collect()

        TerminalUI.printSingle("Sentinel Status", style: .bold)
        TerminalUI.printSeparator()
        TerminalUI.space()

        for row in StatusFormatter.rows(for: snapshot) {
            let label = row.label.padding(toLength: 18, withPad: " ", startingAt: 0)
            TerminalUI.printSingle("\(label) \(row.value)", style: row.style)
        }

        TerminalUI.space()
    }
}
