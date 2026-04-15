import Darwin
import Foundation

enum LaunchAgentHealthCheck {
    static func validateInstalledFiles(configuration: Configuration, sourceExecutableURL: URL) throws {
        try validatePlist(at: configuration.agentPlistURL, expectedExecutablePath: configuration.agentInstallPath)
        try validateExecutable(at: configuration.agentInstallURL, sourceExecutableURL: sourceExecutableURL)
    }

    static func verifyRuntimeReadiness(
        launchctl: LaunchctlClient,
        serviceTarget: String,
        expectedLabel: String
    ) throws {
        let result = launchctl.printService(serviceTarget)
        guard result.isSuccess else {
            throw AgentError.verificationFailed("Sentinel agent was installed but launchd did not report it as loaded.")
        }

        if !result.output.isEmpty, !result.output.contains(expectedLabel) {
            throw AgentError.verificationFailed("Launch agent status did not match the expected service label.")
        }
    }

    private static func validatePlist(at url: URL, expectedExecutablePath: String) throws {
        let data = try Data(contentsOf: url)
        let plist = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)

        guard let dictionary = plist as? [String: Any],
              let arguments = dictionary["ProgramArguments"] as? [String],
              arguments == [expectedExecutablePath] else {
            throw AgentError.verificationFailed("Installed launch agent plist does not match the expected executable path.")
        }

        try validateOwnershipAndPermissions(at: url, maximumPermissions: 0o644)
    }

    private static func validateExecutable(at installedURL: URL, sourceExecutableURL: URL) throws {
        try validateOwnershipAndPermissions(at: installedURL, maximumPermissions: 0o755)

        let sourceFingerprint = FileHasher.sha512(at: sourceExecutableURL)
        let installedFingerprint = FileHasher.sha512(at: installedURL)
        guard sourceFingerprint != nil, sourceFingerprint == installedFingerprint else {
            throw AgentError.verificationFailed("Installed Sentinel executable did not match the requested source binary.")
        }
    }

    private static func validateOwnershipAndPermissions(at url: URL, maximumPermissions: Int) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
        let ownerUserID = attributes[.ownerAccountID] as? Int
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue ?? 0
        let currentUserID = Int(getuid())

        guard ownerUserID == currentUserID else {
            throw AgentError.verificationFailed("Installed launch agent asset has unexpected ownership.")
        }

        guard (permissions & 0o022) == 0, permissions <= maximumPermissions else {
            throw AgentError.verificationFailed("Installed launch agent asset has unsafe filesystem permissions.")
        }
    }
}
