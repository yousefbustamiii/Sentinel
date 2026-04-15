import ArgumentParser
import Foundation

@main
struct SentinelCLI: ParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "sen",
        abstract: "Sentinel | Security Monitoring Engine",
        subcommands: [
            RunCommand.self,
            StopCommand.self,
            StatusCommand.self,
            LogsCommand.self,
            TrustCommand.self,
            PasswordCommand.self,
            DevCommand.self
        ]
    )
}
