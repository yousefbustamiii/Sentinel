import XCTest
@testable import sen

final class LogStoreTests: XCTestCase {
    
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
    }
    
    override func tearDown() {
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }
    
    func testLogStore_AppendAndRead() {
        let store = LogStore() 
        
        let entry = LogEntry(
            eventName: "TestEvent",
            toolName: "UnitTest",
            severity: .info,
            message: "This is a test message",
            category: "test",
            evidence: []
        )
        
        store.append(entry)

        let logs = store.readAll()

        XCTAssertFalse(logs.isEmpty, "Logs should not be empty after append")
        XCTAssertEqual(logs.first?.eventName, "TestEvent")
    }
    
    func testLogStore_Wipe() {
        let store = LogStore()
        let logURL = Configuration.shared.logURL
        let entry = LogEntry(eventName: "A", toolName: "T", severity: .info, message: "M", category: "C", evidence: [])
        store.append(entry)

        XCTAssertTrue(FileManager.default.fileExists(atPath: logURL.path))
        
        store.wipe()

        XCTAssertFalse(FileManager.default.fileExists(atPath: logURL.path))
    }

    func testLogStore_IgnoresPartialFinalLine() throws {
        let store = LogStore()
        let logURL = Configuration.shared.logURL

        let valid = LogEntry(eventName: "Valid", toolName: "UnitTest", severity: .info, message: "ok", category: "test", evidence: [])
        store.append(valid)

        let partial = "{\"event_name\":\"Partial\""
        let handle = try FileHandle(forWritingTo: logURL)
        handle.seekToEndOfFile()
        handle.write(Data(partial.utf8))
        handle.closeFile()

        let logs = store.readAll()

        XCTAssertEqual(logs.count, 1)
        XCTAssertEqual(logs.first?.eventName, "Valid")
    }

    func testLogStore_CreatesRestrictedPermissions() throws {
        let store = LogStore()
        let logURL = Configuration.shared.logURL
        let entry = LogEntry(eventName: "A", toolName: "T", severity: .info, message: "M", category: "C", evidence: [])

        store.append(entry)

        let attributes = try FileManager.default.attributesOfItem(atPath: logURL.path)
        let permissions = try XCTUnwrap(attributes[.posixPermissions] as? NSNumber)

        XCTAssertEqual(permissions.intValue, 0o600)
    }

    func testLogStore_RotatesWhenSizeExceedsLimit() throws {
        let store = LogStore()
        let currentURL = Configuration.shared.logURL
        let rotatedURL = currentURL.deletingPathExtension().appendingPathExtension("log.1")

        for index in 0..<2200 {
            store.append(LogEntry(
                eventName: "Event\(index)",
                toolName: "UnitTest",
                severity: .info,
                message: String(repeating: "x", count: 400),
                category: "test",
                evidence: []
            ))
        }

        XCTAssertTrue(FileManager.default.fileExists(atPath: currentURL.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: rotatedURL.path))
        XCTAssertFalse(store.readAll().isEmpty)
    }
}
