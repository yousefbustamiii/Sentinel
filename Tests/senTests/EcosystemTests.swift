import XCTest
@testable import sen

final class EcosystemTests: XCTestCase {
    
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
        
        // Ensure TrustManager is initialized with the new path
        TrustManager.shared.reset()
        TrustManager.shared.initialize()
    }
    
    override func tearDown() {
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }

    private func clearTrustStore() {
        while !TrustManager.shared.entries.isEmpty {
            XCTAssertTrue(TrustManager.shared.revoke(at: 0))
        }
    }
    
    func testHomebrewIntegrity_WithValidStructure_ReturnsTrue() throws {
        let brewRoot = tempRoot.appendingPathComponent("homebrew")
        try FileManager.default.createDirectory(at: brewRoot.appendingPathComponent("bin"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: brewRoot.appendingPathComponent("etc"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: brewRoot.appendingPathComponent("var"), withIntermediateDirectories: true)
        try "fake_brew".write(to: brewRoot.appendingPathComponent("bin/brew"), atomically: true, encoding: .utf8)
        
        XCTAssertTrue(EcosystemManager.verifyHomebrewIntegrity(root: brewRoot))
    }
    
    func testHomebrewIntegrity_WithMissingEtc_ReturnsFalse() throws {
        let brewRoot = tempRoot.appendingPathComponent("bad_brew")
        try FileManager.default.createDirectory(at: brewRoot.appendingPathComponent("bin"), withIntermediateDirectories: true)
        try "fake_brew".write(to: brewRoot.appendingPathComponent("bin/brew"), atomically: true, encoding: .utf8)
        
        XCTAssertFalse(EcosystemManager.verifyHomebrewIntegrity(root: brewRoot))
    }
    
    func testHydrate_PinsBinariesCorrectly() throws {
        // Setup a mock brew bin directory
        let mockBrewBin = tempRoot.appendingPathComponent("opt/homebrew/bin")
        let mockBrewRoot = tempRoot.appendingPathComponent("opt/homebrew")
        try FileManager.default.createDirectory(at: mockBrewBin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: mockBrewRoot.appendingPathComponent("etc"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: mockBrewRoot.appendingPathComponent("var"), withIntermediateDirectories: true)
        
        let cellarBin = mockBrewRoot.appendingPathComponent("Cellar/pkg/1.0/bin")
        try FileManager.default.createDirectory(at: cellarBin, withIntermediateDirectories: true)

        let tool1Target = cellarBin.appendingPathComponent("tool1")
        let tool2Target = cellarBin.appendingPathComponent("tool2")
        try "#!/bin/sh\nexit 0\n".write(to: tool1Target, atomically: true, encoding: .utf8)
        try "#!/bin/sh\nexit 0\n".write(to: tool2Target, atomically: true, encoding: .utf8)
        try "#!/bin/sh\nexit 0\n".write(to: mockBrewBin.appendingPathComponent("brew"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool1Target.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool2Target.path)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: mockBrewBin.appendingPathComponent("brew").path)

        let tool1 = mockBrewBin.appendingPathComponent("tool1")
        let tool2 = mockBrewBin.appendingPathComponent("tool2")
        try FileManager.default.createSymbolicLink(at: tool1, withDestinationURL: tool1Target)
        try FileManager.default.createSymbolicLink(at: tool2, withDestinationURL: tool2Target)
        
        // Hydrate
        let report = EcosystemManager.hydrate(using: [mockBrewBin.path])
        
        XCTAssertEqual(report.addedEntries, 3)
        XCTAssertEqual(report.skippedEntries, 0)
        XCTAssertTrue(TrustManager.shared.isTrusted(path: tool1Target.path))
        XCTAssertTrue(TrustManager.shared.isTrusted(path: tool2Target.path))
        XCTAssertTrue(TrustManager.shared.isTrusted(path: tool1.path))

        let trustedTool = try XCTUnwrap(TrustManager.shared.entries.first(where: { $0.path == tool1Target.path }))
        XCTAssertEqual(trustedTool.kind, .ecosystem)
        XCTAssertEqual(trustedTool.provenance, "HOMEBREW_ARM64")
        XCTAssertEqual(trustedTool.resolvedPath, tool1Target.path)
        XCTAssertEqual(trustedTool.fileType, FileAttributeType.typeRegular.rawValue)
        
        // Verify fingerprint logic (tampering check)
        try "#!/bin/sh\necho tampered\n".write(to: tool1Target, atomically: true, encoding: .utf8)
        XCTAssertEqual(TrustManager.shared.checkStatus(path: tool1Target.path), .tampered)
    }

    func testHydrate_SkipsWorldWritableTargets() throws {
        clearTrustStore()

        let mockBrewBin = tempRoot.appendingPathComponent("opt/homebrew/bin")
        let mockBrewRoot = tempRoot.appendingPathComponent("opt/homebrew")
        try FileManager.default.createDirectory(at: mockBrewBin, withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: mockBrewRoot.appendingPathComponent("etc"), withIntermediateDirectories: true)
        try FileManager.default.createDirectory(at: mockBrewRoot.appendingPathComponent("var"), withIntermediateDirectories: true)
        try "#!/bin/sh\nexit 0\n".write(to: mockBrewBin.appendingPathComponent("brew"), atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: mockBrewBin.appendingPathComponent("brew").path)

        let cellarBin = mockBrewRoot.appendingPathComponent("Cellar/pkg/1.0/bin")
        try FileManager.default.createDirectory(at: cellarBin, withIntermediateDirectories: true)
        let suspiciousTarget = cellarBin.appendingPathComponent("tool3")
        let link = mockBrewBin.appendingPathComponent("tool3")

        try "#!/bin/sh\nexit 0\n".write(to: suspiciousTarget, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o777], ofItemAtPath: suspiciousTarget.path)
        try FileManager.default.createSymbolicLink(at: link, withDestinationURL: suspiciousTarget)

        let report = EcosystemManager.hydrate(using: [mockBrewBin.path])

        XCTAssertEqual(report.addedEntries, 1)
        XCTAssertEqual(report.skippedEntries, 1)
        XCTAssertFalse(TrustManager.shared.isTrusted(path: suspiciousTarget.path))
    }
}
