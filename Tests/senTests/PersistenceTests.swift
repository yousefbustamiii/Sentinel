import XCTest
@testable import sen

final class PersistenceTests: XCTestCase {
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
        PersistenceStateStore.shared.reset()
    }

    override func tearDown() {
        PersistenceStateStore.shared.reset()
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }
    
    func testGetBinaryTarget_WithProgramKey() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        
        let plistURL = tempDir.appendingPathComponent("test.plist")
        let dict: [String: Any] = ["Program": "/usr/local/bin/mytool"]
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try data.write(to: plistURL)
        
        let scanner = PersistenceScanner()
        let result = scanner.getBinaryTarget(from: plistURL)
        
        XCTAssertEqual(result, "/usr/local/bin/mytool")
    }

    func testGetBinaryTarget_WithProgramArguments() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        
        let plistURL = tempDir.appendingPathComponent("test_args.plist")
        let dict: [String: Any] = ["ProgramArguments": ["/usr/bin/python3", "script.py"]]
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try data.write(to: plistURL)
        
        let scanner = PersistenceScanner()
        let result = scanner.getBinaryTarget(from: plistURL)
        
        XCTAssertEqual(result, "/usr/bin/python3")
    }

    func testPerformScan_FirstRunBaselinesExistingItems() throws {
        let launchDir = tempRoot.appendingPathComponent("LaunchAgents")
        try FileManager.default.createDirectory(at: launchDir, withIntermediateDirectories: true)
        let plistURL = launchDir.appendingPathComponent("existing.plist")
        try writePlist(["Program": "/usr/bin/true"], to: plistURL)

        let scanner = PersistenceScanner(persistenceDirs: [launchDir.path])
        var reports = 0
        scanner.onResultDetected = { _ in reports += 1 }

        scanner.performScan()

        XCTAssertEqual(reports, 0)
        let state = PersistenceStateStore.shared.currentState()
        XCTAssertTrue(state.hasCompletedInitialBaseline)
        XCTAssertNotNil(state.items[plistURL.path])
    }

    func testPerformScan_ChangedTargetReportsTampering() throws {
        let launchDir = tempRoot.appendingPathComponent("LaunchAgents")
        try FileManager.default.createDirectory(at: launchDir, withIntermediateDirectories: true)
        let plistURL = launchDir.appendingPathComponent("agent.plist")
        try writePlist(["Program": "/usr/bin/true"], to: plistURL)

        let scanner = PersistenceScanner(persistenceDirs: [launchDir.path])
        scanner.performScan()

        try writePlist(["Program": "/bin/sh"], to: plistURL)

        let expectation = XCTestExpectation(description: "reports changed target")
        scanner.onResultDetected = { result in
            switch result {
            case .observation(let threat), .alert(let threat):
                XCTAssertTrue(threat.evidence.contains { $0.code == .tamperingDetected })
                expectation.fulfill()
            case .none:
                break
            }
        }

        scanner.performScan()
        wait(for: [expectation], timeout: 1.0)
    }

    func testPerformScan_CorruptedPlistReportsTampering() throws {
        let launchDir = tempRoot.appendingPathComponent("LaunchAgents")
        try FileManager.default.createDirectory(at: launchDir, withIntermediateDirectories: true)
        let plistURL = launchDir.appendingPathComponent("broken.plist")
        try writePlist(["Program": "/usr/bin/true"], to: plistURL)

        let scanner = PersistenceScanner(persistenceDirs: [launchDir.path])
        scanner.performScan()

        try Data("not-a-plist".utf8).write(to: plistURL)

        let expectation = XCTestExpectation(description: "reports corrupt plist")
        scanner.onResultDetected = { result in
            switch result {
            case .observation(let threat), .alert(let threat):
                XCTAssertTrue(threat.evidence.contains { $0.description.contains("not a valid property list") })
                expectation.fulfill()
            case .none:
                break
            }
        }

        scanner.performScan()
        wait(for: [expectation], timeout: 1.0)
    }

    func testPersistenceStateStore_RecoversFromBackupWhenPrimaryIsCorrupted() throws {
        let snapshot = PersistenceManifestSnapshot(
            path: "/Library/LaunchAgents/test.plist",
            fileHash: "hash",
            targetPath: "/usr/bin/true",
            signerTeamID: "TEAM123",
            lastModified: Date(),
            isValidPropertyList: true,
            parseError: nil
        )

        PersistenceStateStore.shared.bootstrap(with: [snapshot])
        XCTAssertTrue(FileManager.default.fileExists(atPath: PersistenceStatePath.url.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: PersistenceStatePath.backupURL.path))

        try Data("corrupt".utf8).write(to: PersistenceStatePath.url, options: .atomic)

        PersistenceStateStore.shared.reset()
        let state = PersistenceStateStore.shared.currentState()

        XCTAssertTrue(state.hasCompletedInitialBaseline)
        XCTAssertEqual(state.items[snapshot.path]?.targetPath, snapshot.targetPath)
    }

    private func writePlist(_ dict: [String: Any], to url: URL) throws {
        let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)
        try data.write(to: url)
    }
}

final class USBScannerTests: XCTestCase {
    
    func testIsKnownAttackHardware_WithMaliciousNames() {
        let scanner = USBScanner()
        XCTAssertTrue(scanner.isKnownAttackHardware("RubberDucky"))
        XCTAssertTrue(scanner.isKnownAttackHardware("BashBunny_v2"))
        XCTAssertTrue(scanner.isKnownAttackHardware("pwnagotchi-1"))
        XCTAssertTrue(scanner.isKnownAttackHardware("Flipper Zero"))
    }
    
    func testIsKnownAttackHardware_WithSafeNames() {
        let scanner = USBScanner()
        XCTAssertFalse(scanner.isKnownAttackHardware("Work Backup"))
        XCTAssertFalse(scanner.isKnownAttackHardware("Photos"))
        XCTAssertFalse(scanner.isKnownAttackHardware("Time Machine"))
    }
}
