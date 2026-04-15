import Foundation

/// Centralized configuration for the Sentinel Security Engine.
public struct Configuration {
    public static var shared = Configuration()
    
    // MARK: - Core Branding
    
    public let productName: String      = "Sentinel"
    public let bundleID: String         = "com.sentinel.mac"
    public let agentLabel: String       = "com.sentinel.mac.agent"
    
    // MARK: - Security Constraints
    
    public let keychainService: String  = "com.sentinel.mac.auth"
    public let keychainAccount: String  = "admin_lock"
    
    // MARK: - Execution Cadences
    
    public let processInterval: TimeInterval     = 3.0
    public let networkInterval: TimeInterval     = 5.0
    public let usbInterval: TimeInterval         = 10.0
    public let persistenceInterval: TimeInterval = 60.0
    
    private init() {}
    
    // MARK: - Path Resolution
    
    public var customRootDirectory: URL?
    
    public var rootDirectory: URL {
        customRootDirectory ?? URL(fileURLWithPath: NSHomeDirectory()).appending(path: ".sen")
    }
    
    public var customExecutablePath: String?
    
    public var executablePath: String {
        customExecutablePath
            ?? ExecutablePathResolver.currentExecutablePath()
            ?? "/usr/local/bin/sen"
    }
    
    public var agentInstallURL: URL {
        rootDirectory.appending(path: "sentinel_agent")
    }
    
    public var findingsURL: URL { rootDirectory.appending(path: "findings.json") }
    public var logURL: URL      { rootDirectory.appending(path: "forensics.log") }
    public var trustURL: URL    { rootDirectory.appending(path: "trust.json") }
    public var persistenceStateURL: URL { rootDirectory.appending(path: "persistence_state.json") }
    public var rateLimitStateURL: URL { rootDirectory.appending(path: "rate_limits.json") }
    
    public var customLaunchAgentsDirectory: URL?
    
    public var launchAgentsDirectory: URL {
        customLaunchAgentsDirectory
            ?? URL(fileURLWithPath: NSHomeDirectory()).appending(path: "Library").appending(path: "LaunchAgents")
    }
    
    public var agentPlistURL: URL {
        launchAgentsDirectory.appending(path: "\(agentLabel).plist")
    }
    
    public var agentPlistPath: String   { agentPlistURL.path }
    public var agentInstallPath: String { agentInstallURL.path }
}
