import XCTest
@testable import sen

final class ScannerTests: XCTestCase {
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
        NetworkListenerBaselineStore.shared.reset()
    }

    override func tearDown() {
        NetworkListenerBaselineStore.shared.reset()
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }
    
    func testUSBContentInspector_WithSuspiciousFiles_ReturnsEvidence() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }
        
        // Create suspicious files
        try "test".write(to: tempDir.appendingPathComponent(".hidden_payload"), atomically: true, encoding: .utf8)
        try "test".write(to: tempDir.appendingPathComponent("exploit_script.sh"), atomically: true, encoding: .utf8)
        try "test".write(to: tempDir.appendingPathComponent("normal_file.txt"), atomically: true, encoding: .utf8)
        
        let evidence = USBContentInspector.inspect(volume: tempDir)
        
        XCTAssertEqual(evidence.count, 3)
        
        XCTAssertTrue(evidence.contains { $0.code == .hiddenRootItem })
        XCTAssertTrue(evidence.contains { $0.code == .suspiciousFilename })
        XCTAssertTrue(evidence.contains { $0.code == .executableAtRoot })
    }

    func testUSBContentInspector_IgnoresCommonMacOSRootArtifacts() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try "test".write(to: tempDir.appendingPathComponent(".Trashes"), atomically: true, encoding: .utf8)
        try "test".write(to: tempDir.appendingPathComponent(".Spotlight-V100"), atomically: true, encoding: .utf8)
        try "test".write(to: tempDir.appendingPathComponent(".fseventsd"), atomically: true, encoding: .utf8)
        try "test".write(to: tempDir.appendingPathComponent(".DS_Store"), atomically: true, encoding: .utf8)

        let evidence = USBContentInspector.inspect(volume: tempDir)

        XCTAssertTrue(evidence.isEmpty)
    }

    func testUSBContentInspector_DoesNotTreatGenericInstallerAsSuspiciousFilename() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try "test".write(to: tempDir.appendingPathComponent("FirmwareUpdate.pkg"), atomically: true, encoding: .utf8)

        let evidence = USBContentInspector.inspect(volume: tempDir)

        XCTAssertFalse(evidence.contains { $0.code == .suspiciousFilename })
        XCTAssertFalse(evidence.contains { $0.code == .executableAtRoot })
    }

    func testUSBContentInspector_FlagsSuspiciousExecutableNameContextually() throws {
        let tempDir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        try "test".write(to: tempDir.appendingPathComponent("payload_dropper.pkg"), atomically: true, encoding: .utf8)

        let evidence = USBContentInspector.inspect(volume: tempDir)

        XCTAssertTrue(evidence.contains { $0.code == .suspiciousFilename })
        XCTAssertTrue(evidence.contains { $0.code == .executableAtRoot })
    }

    func testNetworkListenerParser_ParsesStructuredLsofOutput() {
        let output = [
            "p1234",
            "cnode",
            "u501",
            "f21",
            "n127.0.0.1:3000",
            "p2222",
            "cpython",
            "u0",
            "f7",
            "n*:4444"
        ].joined(separator: "\n")

        let listeners = NetworkListenerParser.parse(output)

        XCTAssertEqual(listeners.count, 2)
        XCTAssertEqual(listeners[0].processIdentifier, 1234)
        XCTAssertEqual(listeners[0].processName, "node")
        XCTAssertEqual(listeners[0].endpointPort, 3000)
        XCTAssertTrue(listeners[0].isLocalOnly)
        XCTAssertEqual(listeners[1].endpointPort, 4444)
        XCTAssertFalse(listeners[1].isLocalOnly)
    }

    func testNetworkListenerHeuristics_IgnoresLocalDevelopmentListeners() {
        let listener = NetworkListenerSnapshot(
            processIdentifier: 1234,
            processName: "node",
            userID: 501,
            userName: "dev",
            endpointHost: "127.0.0.1",
            endpointPort: 3000,
            isLocalOnly: true
        )

        XCTAssertTrue(NetworkListenerHeuristics.shouldIgnore(listener: listener, executablePath: "/Users/test/project/node"))
    }

    func testNetworkListenerHeuristics_DoesNotIgnorePathlessDevelopmentListener() {
        let listener = NetworkListenerSnapshot(
            processIdentifier: 1234,
            processName: "node",
            userID: 501,
            userName: "dev",
            endpointHost: "127.0.0.1",
            endpointPort: 3000,
            isLocalOnly: true
        )

        XCTAssertFalse(NetworkListenerHeuristics.shouldIgnore(listener: listener, executablePath: nil))
    }

    func testNetworkListenerHeuristics_RequiresStrongerSignalWhenPathMissing() {
        let listener = NetworkListenerSnapshot(
            processIdentifier: 2222,
            processName: "python",
            userID: 501,
            userName: "dev",
            endpointHost: "127.0.0.1",
            endpointPort: 4444,
            isLocalOnly: true
        )

        XCTAssertFalse(NetworkListenerHeuristics.hasMeaningfulNetworkSignal(
            listener: listener,
            hasExecutablePath: false,
            isRecurring: false,
            isSignatureValid: true
        ))
        XCTAssertTrue(NetworkListenerHeuristics.hasMeaningfulNetworkSignal(
            listener: listener,
            hasExecutablePath: false,
            isRecurring: false,
            isSignatureValid: false
        ))
    }

    func testNetworkListenerBaselineStore_PersistsRollingSnapshot() {
        let store = NetworkListenerBaselineStore()
        let identity = "501|node|127.0.0.1|3000"

        XCTAssertFalse(store.observe(identity: identity))

        let reloadedStore = NetworkListenerBaselineStore()
        XCTAssertTrue(reloadedStore.observe(identity: identity))
        XCTAssertTrue(FileManager.default.fileExists(atPath: NetworkListenerBaselinePath.url.path))
    }

    func testNetworkListenerBaselineStore_PrunesExpiredEntries() {
        let store = NetworkListenerBaselineStore()
        let identity = "501|node|127.0.0.1|3000"
        let firstSeen = Date(timeIntervalSince1970: 0)
        let muchLater = firstSeen.addingTimeInterval((8 * 24 * 60 * 60))

        XCTAssertFalse(store.observe(identity: identity, now: firstSeen))
        XCTAssertFalse(store.observe(identity: identity, now: muchLater))
    }

    func testNetworkListenerBaselineStore_CorruptedStateFallsBackCleanly() throws {
        let url = NetworkListenerBaselinePath.url
        StorageUtils.ensureDirectoryExists(for: url)
        try Data("corrupt".utf8).write(to: url, options: .atomic)

        let store = NetworkListenerBaselineStore()
        XCTAssertFalse(store.observe(identity: "501|python|127.0.0.1|4444"))

        let rewritten = try Data(contentsOf: url)
        XCTAssertFalse(rewritten.isEmpty)
    }
}
