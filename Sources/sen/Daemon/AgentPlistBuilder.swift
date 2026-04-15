import Foundation

/// Constructs the launchd property list configuration for the Sentinel background service.
internal struct AgentPlistBuilder {

    /// Generates launchd plist data for the Sentinel agent.
    static func build(label: String, executableURL: URL) throws -> Data {
        let configuration = Configuration.shared
        let plist: [String: Any] = [
            "Label": label,
            "ProgramArguments": [executableURL.path],
            "RunAtLoad": true,
            "KeepAlive": true,
            "StandardOutPath": configuration.rootDirectory.appending(path: "agent.log").path,
            "StandardErrorPath": configuration.rootDirectory.appending(path: "agent.err").path
        ]

        return try PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0)
    }
}
