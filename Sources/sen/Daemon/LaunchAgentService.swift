import Foundation

/// Errors that may occur during agent install or uninstall.
public enum AgentError: Error {
    case executableCopyFailed(Error)
    case plistWriteFailed(Error)
    case launchctlFailed(code: Int32, output: String)
    case verificationFailed(String)
}

/// Structured failure cases returned by uninstall().
public enum UninstallFailure {
    case launchctlFailed(output: String)
    case fileRemovalFailed(path: String, reason: String)
}

/// Orchestrates Sentinel background service lifecycle operations.
internal final class LaunchAgentService {
    static let shared = LaunchAgentService()

    private let launchctl: LaunchctlClient

    init(launchctl: LaunchctlClient = .live) {
        self.launchctl = launchctl
    }

    /// Installs and registers the agent with the system service manager.
    func installAndStart() throws {
        let conf = Configuration.shared

        do {
            try LaunchAgentInstaller.installExecutable(
                from: URL(fileURLWithPath: conf.executablePath),
                to: conf.agentInstallURL
            )
        } catch {
            throw AgentError.executableCopyFailed(error)
        }

        do {
            let plist = try AgentPlistBuilder.build(label: conf.agentLabel, executableURL: conf.agentInstallURL)
            try LaunchAgentInstaller.writePlist(plist, to: conf.agentPlistURL)
        } catch {
            throw AgentError.plistWriteFailed(error)
        }

        try LaunchAgentHealthCheck.validateInstalledFiles(
            configuration: conf,
            sourceExecutableURL: URL(fileURLWithPath: conf.executablePath)
        )

        try repairAndBootstrap()
    }

    /// Stops the Sentinel background service.
    func stop() throws {
        let conf = Configuration.shared
        try bestEffortBootout(plistPath: conf.agentPlistPath, label: conf.agentLabel)

        if isRunning() {
            throw AgentError.verificationFailed("Sentinel agent remained loaded after bootout.")
        }
    }

    /// Unloads the service and removes its local assets.
    @discardableResult
    func uninstall() -> [UninstallFailure] {
        let conf = Configuration.shared
        var failures: [UninstallFailure] = []

        do {
            try bestEffortBootout(plistPath: conf.agentPlistPath, label: conf.agentLabel)
        } catch let AgentError.launchctlFailed(_, output) {
            failures.append(.launchctlFailed(output: output))
        } catch let AgentError.verificationFailed(message) {
            failures.append(.launchctlFailed(output: message))
        } catch {
            failures.append(.launchctlFailed(output: error.localizedDescription))
        }

        for path in [conf.agentPlistPath, conf.agentInstallPath] {
            do {
                if FileManager.default.fileExists(atPath: path) {
                    try FileManager.default.removeItem(atPath: path)
                }
            } catch {
                failures.append(.fileRemovalFailed(path: path, reason: error.localizedDescription))
            }
        }

        return failures
    }

    /// Checks if the Sentinel service is currently active.
    func isRunning() -> Bool {
        launchctl.isLoaded(serviceTarget: LaunchctlDomain.serviceTarget(label: Configuration.shared.agentLabel))
    }

    private func repairAndBootstrap() throws {
        let conf = Configuration.shared
        let domain = LaunchctlDomain.user
        let serviceTarget = LaunchctlDomain.serviceTarget(label: conf.agentLabel)

        try bestEffortBootout(plistPath: conf.agentPlistPath, label: conf.agentLabel)

        let bootstrap = launchctl.bootstrap(domain, conf.agentPlistPath)
        guard bootstrap.isSuccess else {
            throw AgentError.launchctlFailed(code: bootstrap.status, output: bootstrap.output)
        }

        let kickstart = launchctl.kickstart(serviceTarget)
        guard kickstart.isSuccess else {
            throw AgentError.launchctlFailed(code: kickstart.status, output: kickstart.output)
        }

        try LaunchAgentHealthCheck.verifyRuntimeReadiness(
            launchctl: launchctl,
            serviceTarget: serviceTarget,
            expectedLabel: conf.agentLabel
        )
    }

    private func bestEffortBootout(plistPath: String, label: String) throws {
        let domain = LaunchctlDomain.user
        let serviceTarget = LaunchctlDomain.serviceTarget(label: label)
        let results = [
            launchctl.bootout(domain, serviceTarget),
            launchctl.bootout(domain, plistPath)
        ]

        if let failure = results.first(where: { !$0.isSuccess && !isIgnorableBootoutFailure($0.output) }) {
            throw AgentError.launchctlFailed(code: failure.status, output: failure.output)
        }
    }

    private func isIgnorableBootoutFailure(_ output: String) -> Bool {
        let normalized = output.lowercased()
        return normalized.contains("could not find service")
            || normalized.contains("service is not loaded")
            || normalized.contains("no such process")
            || normalized.contains("not loaded")
    }
}
