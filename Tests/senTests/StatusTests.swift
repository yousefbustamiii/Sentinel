import XCTest
@testable import sen

final class StatusTests: XCTestCase {
    var tempRoot: URL!
    var originalConfig: Configuration!

    override func setUp() {
        super.setUp()
        originalConfig = Configuration.shared
        tempRoot = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try? FileManager.default.createDirectory(at: tempRoot, withIntermediateDirectories: true)

        var config = Configuration.shared
        config.customRootDirectory = tempRoot.appendingPathComponent(".sen")
        Configuration.shared = config

        TrustManager.shared.reset()
        FindingStore.shared.reset()
        PersistenceStateStore.shared.reset()
    }

    override func tearDown() {
        TrustManager.shared.reset()
        FindingStore.shared.reset()
        PersistenceStateStore.shared.reset()
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }

    func testStatusSnapshot_CollectsOperationalState() {
        TrustManager.shared.initialize()
        _ = TrustManager.shared.authorize(TrustEntry(kind: .exactPath, path: "/tmp/test"))
        _ = FindingStore.shared.record(category: "process", name: "tool", path: "/tmp/tool")
        let record = FindingStore.shared.record(category: "process", name: "tool-alert", path: "/tmp/tool-alert")
        FindingStore.shared.markAlerted(id: record.id)
        LogManager.record(LogEntry(
            eventName: "status.test",
            toolName: "StatusTests",
            severity: .info,
            message: "status snapshot test",
            category: "test"
        ))
        PersistenceStateStore.shared.bootstrap(with: [
            PersistenceManifestSnapshot(
                path: "/Library/LaunchAgents/test.plist",
                fileHash: "hash",
                targetPath: "/tmp/tool",
                signerTeamID: nil,
                lastModified: Date(),
                isValidPropertyList: true,
                parseError: nil
            )
        ])

        let snapshot = StatusSnapshot.collect(isAgentLoaded: { true })

        XCTAssertEqual(snapshot.trustEntryCount, 1)
        XCTAssertEqual(snapshot.findingRecordCount, 2)
        XCTAssertTrue(snapshot.hasCompletedPersistenceBaseline)
        XCTAssertEqual(snapshot.persistenceItemCount, 1)
        XCTAssertTrue(snapshot.isAgentLoaded)
        XCTAssertNotNil(snapshot.lastAlertAt)
        XCTAssertNotNil(snapshot.lastLogAt)
    }

    func testStatusFormatter_ProducesStableRowSet() {
        let snapshot = StatusSnapshot(
            isAgentLoaded: true,
            isDeveloperModeActive: false,
            developerModeDescription: "Inactive",
            trustEntryCount: 2,
            findingRecordCount: 3,
            lastAlertAt: Date(timeIntervalSince1970: 0),
            lastLogAt: "2026-01-01T00:00:00Z",
            hasCompletedPersistenceBaseline: true,
            persistenceItemCount: 4
        )

        let rows = StatusFormatter.rows(for: snapshot)

        XCTAssertEqual(rows.count, 7)
        XCTAssertEqual(rows.first?.label, "Agent")
        XCTAssertEqual(rows.first?.value, "Loaded")
        XCTAssertEqual(rows.last?.label, "Persistence State")
    }
}
