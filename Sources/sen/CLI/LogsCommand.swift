import ArgumentParser
import Foundation

struct LogsCommand: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "logs",
        abstract: "Review historical forensic security records"
    )

    @Flag(name: .shortAndLong, help: "Output forensic data in raw JSON format")
    var raw = false

    mutating func run() throws {
        guard CommandRateLimitGuard.enforce(.logs) else { return }

        TerminalUI.space()
        
        let logs = LogManager.fetch()

        if logs.isEmpty {
            TerminalUI.printSingle("Forensic data store is currently empty.", style: .muted)
            TerminalUI.space()
            return
        }

        if raw {
            TerminalUI.printLogEntriesJSON(logs)
        } else {
            TerminalUI.printSingle("Sentinel Log", style: .boldMuted)
            TerminalUI.printSeparator()
            TerminalUI.space()
            TerminalUI.printLogEntries(logs)
        }
        
        TerminalUI.space()
    }
}
