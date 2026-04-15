import XCTest
@testable import sen

final class EnvironmentTests: XCTestCase {
    var tempRoot: URL!
    var originalConfig: Configuration!

    override func setUp() {
        super.setUp()
        originalConfig = Configuration.shared
        tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)

        var config = Configuration.shared
        config.customRootDirectory = tempRoot
        Configuration.shared = config
        DevModeManager.shared.disable()
    }

    override func tearDown() {
        DevModeManager.shared.disable()
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }

    func testHeuristicContext_LooksOperationallyBenign_ForSignedInteractiveStableProcess() {
        let context = HeuristicContext(
            path: "/usr/local/bin/tool",
            processName: "tool",
            parentProcessName: "Terminal",
            isSignatureValid: true,
            isInteractive: true,
            hasPersistence: false,
            listenerPort: nil,
            isRecurringListener: false
        )

        XCTAssertTrue(context.looksOperationallyBenign)
        XCTAssertFalse(context.hasSuspiciousAncestry)
    }

    func testHeuristicContext_RecurringProcessSighting_BecomesTrueForOlderOrRepeatedProcess() {
        let oldContext = HeuristicContext(
            firstSeenAt: Date().addingTimeInterval(-2 * 24 * 60 * 60),
            existingSightingCount: 1
        )
        let repeatedContext = HeuristicContext(
            firstSeenAt: Date(),
            existingSightingCount: 3
        )

        XCTAssertTrue(oldContext.isRecurringProcessSighting)
        XCTAssertTrue(repeatedContext.isRecurringProcessSighting)
    }

    func testHeuristicContext_HasSuspiciousAncestry_ForNonInteractiveUnsignedChain() {
        let context = HeuristicContext(
            path: "/tmp/payload",
            parentProcessName: "bash",
            grandparentProcessName: "launchd",
            isSignatureValid: false,
            isInteractive: false
        )

        XCTAssertTrue(context.hasSuspiciousAncestry)
    }

    func testDevModeManager_CorruptedStateIsInactive() throws {
        let corruptURL = tempRoot.appendingPathComponent("devmode.json")
        try Data("corrupt".utf8).write(to: corruptURL, options: .atomic)

        XCTAssertFalse(DevModeManager.shared.isActive())
        XCTAssertNil(DevModeManager.shared.currentState())
    }

    func testDevModeManager_ExpiredStateIsInactive() throws {
        let expired = DevModeState(duration: .timed(until: Date().addingTimeInterval(-60)))
        let data = try StorageUtils.encoder.encode(expired)
        try data.write(to: tempRoot.appendingPathComponent("devmode.json"), options: .atomic)

        XCTAssertFalse(DevModeManager.shared.isActive())
        XCTAssertNil(DevModeManager.shared.currentState())
    }
}
