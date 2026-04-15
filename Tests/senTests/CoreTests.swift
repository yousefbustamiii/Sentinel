import XCTest
@testable import sen

final class CoreTests: XCTestCase {
    func testDetectionState_ReportsOnlyOnEscalation() {
        var state = DetectionState()

        XCTAssertFalse(state.shouldReport(identity: "abc", level: .none))
        XCTAssertTrue(state.shouldReport(identity: "abc", level: .observation))
        XCTAssertFalse(state.shouldReport(identity: "abc", level: .observation))
        XCTAssertTrue(state.shouldReport(identity: "abc", level: .alert))
        XCTAssertFalse(state.shouldReport(identity: "abc", level: .alert))
    }

    func testLogEntryFormatter_IncludesEvidenceTrace() {
        let log = LogEntry(
            eventName: "scanner.detected",
            toolName: "ProcessScanner",
            severity: .warning,
            message: "Detected suspicious process",
            category: "process",
            evidence: [
                Evidence(code: .pathAnomaly, description: "Temp execution", source: .process),
                Evidence(code: .suspiciousParent, description: "Odd ancestry", source: .process)
            ]
        )

        let formatted = LogEntryFormatter.format(log)

        XCTAssertTrue(formatted.contains("[WARNING]"))
        XCTAssertTrue(formatted.contains("[process]"))
        XCTAssertTrue(formatted.contains("Evidence Trace:"))
        XCTAssertTrue(formatted.contains("Temp execution"))
        XCTAssertTrue(formatted.contains("Odd ancestry"))
    }

    func testExecutablePathResolver_ReturnsExistingExecutablePath() {
        let path = ExecutablePathResolver.currentExecutablePath()

        XCTAssertNotNil(path)
        if let path {
            XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        }
    }

    func testUSBVolumeIdentity_FallsBackToPathWhenVolumeUUIDUnavailable() {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        XCTAssertEqual(USBVolumeIdentity.sightingIdentity(for: url), url.path)
    }
}
