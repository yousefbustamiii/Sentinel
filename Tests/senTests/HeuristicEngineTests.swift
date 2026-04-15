import XCTest
@testable import sen

final class HeuristicEngineTests: XCTestCase {
    
    func testCheckNameAnomaly_WithCorroboratingContext_ReturnsEvidence() {
        let badName = "TeamViewer-QuickSupport"
        let context = HeuristicContext(
            path: "/tmp/teamviewer",
            processName: badName,
            isSignatureValid: false,
            isInteractive: false
        )
        let evidence = HeuristicEngine.checkNameAnomaly(name: badName, source: .process, context: context)
        
        XCTAssertNotNil(evidence)
        XCTAssertEqual(evidence?.code, .knownToolMatch)
        XCTAssertEqual(evidence?.context, "teamviewer")
    }
    
    func testCheckNameAnomaly_WithStableSignedTool_ReturnsNil() {
        let context = HeuristicContext(
            path: "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer",
            processName: "TeamViewer",
            isSignatureValid: true,
            isInteractive: true,
            firstSeenAt: Date().addingTimeInterval(-3 * 24 * 60 * 60)
        )
        let evidence = HeuristicEngine.checkNameAnomaly(name: "TeamViewer", source: .process, context: context)
        
        XCTAssertNil(evidence)
    }
    
    func testCheckPathAnomaly_WithTmpPath_ReturnsEvidence() {
        let tmpPath = "/tmp/malware"
        let context = HeuristicContext(path: tmpPath, isSignatureValid: false, isInteractive: false)
        let evidence = HeuristicEngine.checkPathAnomaly(path: tmpPath, source: .process, context: context)
        
        XCTAssertNotNil(evidence)
        XCTAssertEqual(evidence?.code, .pathAnomaly)
    }

    func testCheckPathAnomaly_WithDeveloperTemporaryPath_ReturnsNil() {
        let tempPath = "/private/var/folders/ab/cd/T/swift-xyz/build/tool"
        let context = HeuristicContext(
            path: tempPath,
            isSignatureValid: true,
            isInteractive: true,
            firstSeenAt: Date().addingTimeInterval(-2 * 24 * 60 * 60)
        )

        let evidence = HeuristicEngine.checkPathAnomaly(path: tempPath, source: .process, context: context)

        XCTAssertNil(evidence)
    }
    
    func testCheckPathAnomaly_WithHiddenHomePath_ReturnsEvidence() {
        let home = NSHomeDirectory()
        let hiddenPath = home + "/.hidden_script"
        let evidence = HeuristicEngine.checkPathAnomaly(
            path: hiddenPath,
            source: .process,
            context: HeuristicContext(path: hiddenPath)
        )
        
        XCTAssertNotNil(evidence)
        XCTAssertEqual(evidence?.code, .hiddenRootItem)
    }

    func testCheckPathAnomaly_WithKnownDeveloperHiddenPath_ReturnsNil() {
        let home = NSHomeDirectory()
        let hiddenPath = home + "/.nix-profile/bin/tool"
        let evidence = HeuristicEngine.checkPathAnomaly(
            path: hiddenPath,
            source: .process,
            context: HeuristicContext(path: hiddenPath, isSignatureValid: true, isInteractive: true)
        )

        XCTAssertNil(evidence)
    }
    
    func testCheckPathAnomaly_WithStandardPath_ReturnsNil() {
        let standardPath = "/Applications/Safari.app/Contents/MacOS/Safari"
        let evidence = HeuristicEngine.checkPathAnomaly(
            path: standardPath,
            source: .process,
            context: HeuristicContext(path: standardPath, isSignatureValid: true, isInteractive: true)
        )
        
        XCTAssertNil(evidence)
    }
    
    func testCheckPortAnomaly_WithSuspiciousPortAndCorroboration_ReturnsEvidence() {
        let listenerLine = "nc       1234 user   3u  IPv4 0x12345678      0t0  TCP *:4444 (LISTEN)"
        let context = HeuristicContext(
            path: "/tmp/nc",
            processName: "nc",
            isSignatureValid: false,
            listenerPort: 4444
        )

        let evidence = HeuristicEngine.checkPortAnomaly(listenerLine, source: .network, context: context)
        
        XCTAssertNotNil(evidence)
        XCTAssertEqual(evidence?.code, .anomalousPort)
        XCTAssertEqual(evidence?.context, "4444")
    }
    
    func testCheckPortAnomaly_WithoutCorroboration_ReturnsNil() {
        let suspiciousLine = "python   567  root   4u  IPv6 0x87654321      0t0  TCP *:4444 (LISTEN)"
        let context = HeuristicContext(
            path: "/Applications/Python.app/Contents/MacOS/Python",
            processName: "python",
            isSignatureValid: true,
            isInteractive: true,
            listenerPort: 4444
        )
        let evidence = HeuristicEngine.checkPortAnomaly(suspiciousLine, source: .network, context: context)
        
        XCTAssertNil(evidence)
    }

    func testCheckParentAnomaly_WithSuspiciousLineage_ReturnsEvidence() {
        let context = HeuristicContext(
            path: "/tmp/payload",
            processName: "payload",
            parentProcessName: "osascript",
            grandparentProcessName: "launchd",
            isSignatureValid: false,
            isInteractive: false
        )

        let evidence = HeuristicEngine.checkParentAnomaly(source: .process, context: context)

        XCTAssertEqual(evidence?.code, .suspiciousParent)
    }

    func testCheckSearchPathAnomaly_WithUserWritableExecutable_ReturnsEvidence() throws {
        let homeBin = URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("bin", isDirectory: true)
        try FileManager.default.createDirectory(at: homeBin, withIntermediateDirectories: true)

        let executableURL = homeBin.appendingPathComponent("sentinel-test-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: executableURL) }

        try "echo test".write(to: executableURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: executableURL.path)

        let context = HeuristicContext(
            path: executableURL.path,
            isSignatureValid: false,
            isInteractive: false,
            firstSeenAt: Date()
        )

        let evidence = HeuristicEngine.checkSearchPathAnomaly(
            path: executableURL.path,
            source: .process,
            context: context
        )

        XCTAssertEqual(evidence?.code, .searchPathExecution)
    }
}
