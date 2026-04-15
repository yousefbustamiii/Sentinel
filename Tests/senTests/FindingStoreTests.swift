import XCTest
@testable import sen

final class FindingStoreTests: XCTestCase {
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
        FindingStore.shared.reset()
    }

    override func tearDown() {
        FindingStore.shared.reset()
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }

    func testFindingStore_RecoversFromBackupWhenPrimaryIsCorrupted() throws {
        let record = FindingStore.shared.record(category: "PROCESS", name: "App", path: "/tmp/app")
        FindingStore.shared.markAlerted(id: record.id)
        FindingStore.shared.flushForTesting()

        try Data("corrupt".utf8).write(to: Configuration.shared.findingsURL, options: .atomic)

        FindingStore.shared.reset()

        let recovered = FindingStore.shared.existingRecord(category: "PROCESS", name: "App", path: "/tmp/app")
        XCTAssertNotNil(recovered)
        XCTAssertEqual(recovered?.id, record.id)
    }

    func testFindingStore_WritesBackupFile() throws {
        _ = FindingStore.shared.record(category: "NETWORK", name: "Listener", path: "/tmp/listener")
        FindingStore.shared.flushForTesting()

        XCTAssertTrue(FileManager.default.fileExists(atPath: Configuration.shared.findingsURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: FindingStorePath.backupURL.path))
    }
}
