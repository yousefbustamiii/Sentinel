import XCTest
@testable import sen

final class LaunchAgentServiceTests: XCTestCase {
    var tempRoot: URL!
    var originalConfig: Configuration!

    override func setUp() {
        super.setUp()
        originalConfig = Configuration.shared
        tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)
    }

    override func tearDown() {
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }

    func testInstallAndStart_RepairsAndVerifiesLaunchAgent() throws {
        let sourceExecutable = tempRoot.appendingPathComponent("sen")
        let launchAgentsDirectory = tempRoot.appendingPathComponent("LaunchAgents")
        try "#!/bin/sh\nexit 0\n".write(to: sourceExecutable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: sourceExecutable.path)

        var config = Configuration.shared
        config.customRootDirectory = tempRoot.appendingPathComponent(".sen")
        config.customExecutablePath = sourceExecutable.path
        config.customLaunchAgentsDirectory = launchAgentsDirectory
        Configuration.shared = config

        let state = LaunchctlState()
        let service = LaunchAgentService(launchctl: state.client)

        try service.installAndStart()

        XCTAssertTrue(FileManager.default.fileExists(atPath: config.agentInstallPath))
        XCTAssertTrue(FileManager.default.fileExists(atPath: config.agentPlistPath))
        XCTAssertEqual(
            state.operations,
            [
                "bootout:\(LaunchctlDomain.user):\(LaunchctlDomain.serviceTarget(label: config.agentLabel))",
                "bootout:\(LaunchctlDomain.user):\(config.agentPlistPath)",
                "bootstrap:\(LaunchctlDomain.user):\(config.agentPlistPath)",
                "kickstart:\(LaunchctlDomain.serviceTarget(label: config.agentLabel))",
                "print:\(LaunchctlDomain.serviceTarget(label: config.agentLabel))"
            ]
        )

        let plistData = try Data(contentsOf: config.agentPlistURL)
        let plist = try PropertyListSerialization.propertyList(from: plistData, options: [], format: nil) as? [String: Any]
        XCTAssertEqual(plist?["Label"] as? String, config.agentLabel)
        XCTAssertEqual(plist?["ProgramArguments"] as? [String], [config.agentInstallPath])
    }

    func testInstallAndStart_WhenCopyFails_PreservesExistingExecutable() throws {
        let launchAgentsDirectory = tempRoot.appendingPathComponent("LaunchAgents")
        let rootDirectory = tempRoot.appendingPathComponent(".sen")
        try FileManager.default.createDirectory(at: rootDirectory, withIntermediateDirectories: true)
        try "existing".write(to: rootDirectory.appendingPathComponent("sentinel_agent"), atomically: true, encoding: .utf8)

        var config = Configuration.shared
        config.customRootDirectory = rootDirectory
        config.customExecutablePath = tempRoot.appendingPathComponent("missing-sen").path
        config.customLaunchAgentsDirectory = launchAgentsDirectory
        Configuration.shared = config

        let service = LaunchAgentService(launchctl: LaunchctlState().client)

        XCTAssertThrowsError(try service.installAndStart())

        let preserved = try String(contentsOf: config.agentInstallURL, encoding: .utf8)
        XCTAssertEqual(preserved, "existing")
    }

    func testLaunchAgentHealthCheck_RejectsExecutableMismatch() throws {
        let sourceExecutable = tempRoot.appendingPathComponent("sen")
        let installedExecutable = tempRoot.appendingPathComponent("installed-sen")
        let plistURL = tempRoot.appendingPathComponent("com.sentinel.mac.agent.plist")

        try "#!/bin/sh\necho source\n".write(to: sourceExecutable, atomically: true, encoding: .utf8)
        try "#!/bin/sh\necho different\n".write(to: installedExecutable, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: sourceExecutable.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: installedExecutable.path)

        let plist = try AgentPlistBuilder.build(label: "com.sentinel.mac.agent", executableURL: installedExecutable)
        try plist.write(to: plistURL, options: .atomic)
        try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: plistURL.path)

        var config = Configuration.shared
        config.customRootDirectory = tempRoot
        config.customExecutablePath = sourceExecutable.path
        config.customLaunchAgentsDirectory = tempRoot
        Configuration.shared = config

        XCTAssertThrowsError(
            try LaunchAgentHealthCheck.validateInstalledFiles(
                configuration: config,
                sourceExecutableURL: sourceExecutable
            )
        )
    }
}

private final class LaunchctlState {
    var operations: [String] = []
    var loaded = false

    var client: LaunchctlClient {
        LaunchctlClient(
            bootstrap: { [self] domain, plistPath in
                operations.append("bootstrap:\(domain):\(plistPath)")
                loaded = true
                return LaunchctlResult(status: 0, output: "")
            },
            bootout: { [self] domain, target in
                operations.append("bootout:\(domain):\(target)")
                loaded = false
                return LaunchctlResult(status: 3, output: "Could not find service")
            },
            kickstart: { [self] serviceTarget in
                operations.append("kickstart:\(serviceTarget)")
                loaded = true
                return LaunchctlResult(status: 0, output: "")
            },
            printService: { [self] serviceTarget in
                operations.append("print:\(serviceTarget)")
                return LaunchctlResult(status: loaded ? 0 : 3, output: loaded ? "" : "not loaded")
            }
        )
    }
}
