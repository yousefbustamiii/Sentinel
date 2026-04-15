import Darwin
import XCTest
@testable import sen

final class EvidenceTests: XCTestCase {
    
    func testEvidenceInitialization() {
        let code: Evidence.EvidenceCode = .dylibInjection
        let description = "Test description"
        let source: ScannerSource = .process
        let context = "test_context"
        
        let evidence = Evidence(code: code, description: description, source: source, context: context)
        
        XCTAssertEqual(evidence.code, code)
        XCTAssertEqual(evidence.description, description)
        XCTAssertEqual(evidence.source, source)
        XCTAssertEqual(evidence.context, context)
    }
}

final class TrustManagerTests: XCTestCase {
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
        TrustManager.shared.reset()
        TrustManager.shared.initialize()
        clearTrustStore()
    }

    override func tearDown() {
        clearTrustStore()
        TrustManager.shared.reset()
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }

    private func clearTrustStore() {
        while !TrustManager.shared.entries.isEmpty {
            XCTAssertTrue(TrustManager.shared.revoke(at: 0))
        }
    }
    
    func testIsTrusted_WhenNotAdded_ReturnsFalse() {
        let path = "/tmp/unknown_binary"
        XCTAssertFalse(TrustManager.shared.isTrusted(path: path))
    }

    func testIsTrusted_AppleSignedPathWithoutExplicitTrust_ReturnsFalse() {
        XCTAssertFalse(TrustManager.shared.isTrusted(path: "/bin/ls"))
    }
    
    func testTrustWorkflow_AddAndVerify() {
        let tempFile = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString + ".txt")
        let path = tempFile.path
        
        try? "original".write(to: tempFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempFile) }
        
        let entry = TrustEntry(kind: .exactPath, path: path, fingerprint: FileHasher.sha512(at: tempFile))
        XCTAssertFalse(TrustManager.shared.isTrusted(path: path))
        XCTAssertTrue(TrustManager.shared.authorize(entry))
        XCTAssertTrue(TrustManager.shared.isTrusted(path: path))

        let entries = TrustManager.shared.entries
        if let idx = entries.firstIndex(where: { $0.path == path }) {
            XCTAssertTrue(TrustManager.shared.revoke(at: idx))
        }
        XCTAssertFalse(TrustManager.shared.isTrusted(path: path))
    }

    func testCheckStatus_ExactPathDoesNotTrustDescendants() throws {
        let directoryURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let childURL = directoryURL.appendingPathComponent("child")
        try FileManager.default.createDirectory(at: directoryURL, withIntermediateDirectories: true)
        try "child".write(to: childURL, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: directoryURL) }

        _ = TrustManager.shared.authorize(
            TrustEntry(kind: .exactPath, path: directoryURL.path, updatePolicy: .strict)
        )

        XCTAssertEqual(TrustManager.shared.checkStatus(path: childURL.path), .untrusted)
    }

    // MARK: - UpdatePolicy: .strict

    func testCheckStatus_Strict_HashChange_ReturnsTampered() {
        let tempFile = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try? "original".write(to: tempFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        let entry = TrustEntry(
            kind: .exactPath,
            path: tempFile.path,
            fingerprint: FileHasher.sha512(at: tempFile),
            updatePolicy: .strict
        )
        _ = TrustManager.shared.authorize(entry)

        // Tamper: overwrite content
        try? "tampered_content".write(to: tempFile, atomically: true, encoding: .utf8)

        XCTAssertEqual(TrustManager.shared.checkStatus(path: tempFile.path), .tampered)

        // Cleanup trust store
        if let idx = TrustManager.shared.entries.firstIndex(where: { $0.path == tempFile.path }) {
            _ = TrustManager.shared.revoke(at: idx)
        }
    }

    // MARK: - UpdatePolicy: .allowSignedUpdates

    func testCheckStatus_AllowSignedUpdates_HashChange_NoTeamID_ReturnsTampered() {
        // When .allowSignedUpdates but no teamID on entry, a hash change must still be .tampered
        // because we cannot verify "same signer" without a Team ID baseline.
        let tempFile = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try? "original".write(to: tempFile, atomically: true, encoding: .utf8)
        defer { try? FileManager.default.removeItem(at: tempFile) }

        let entry = TrustEntry(
            kind: .appBundle,
            path: tempFile.path,
            fingerprint: FileHasher.sha512(at: tempFile),
            teamID: nil, // No team ID — cannot validate signer
            updatePolicy: .allowSignedUpdates
        )
        _ = TrustManager.shared.authorize(entry)
        try? "tampered_content".write(to: tempFile, atomically: true, encoding: .utf8)

        XCTAssertEqual(TrustManager.shared.checkStatus(path: tempFile.path), .tampered)
    }

    func testTeamIDTrustRequiresExplicitSignerScope() {
        XCTAssertTrue(TrustManager.shared.authorize(
            TrustEntry(kind: .appBundle, path: "/Applications/Trusted.app", teamID: "TEAM123")
        ))
        XCTAssertFalse(TrustManager.shared.isTrusted(teamID: "TEAM123"))

        clearTrustStore()

        XCTAssertTrue(TrustManager.shared.authorize(
            TrustEntry(kind: .signer, path: "/Applications/Trusted.app", teamID: "TEAM123")
        ))
        XCTAssertTrue(TrustManager.shared.isTrusted(teamID: "TEAM123"))
    }

    func testCheckStatus_AppBundleFingerprintUsesExecutableContent() throws {
        let appURL = try makeTestAppBundle()
        defer { try? FileManager.default.removeItem(at: appURL.deletingLastPathComponent()) }

        let integrity = TrustIntegritySnapshotResolver.make(for: appURL, kind: .appBundle)
        let entry = TrustEntry(
            kind: .appBundle,
            path: appURL.path,
            fingerprint: integrity.fingerprint,
            teamID: nil,
            resolvedPath: integrity.resolvedPath,
            fileType: integrity.fileType,
            updatePolicy: .strict
        )
        _ = TrustManager.shared.authorize(entry)

        XCTAssertEqual(TrustManager.shared.checkStatus(path: appURL.path), .trusted)

        let executableURL = appURL.appending(path: "Contents").appending(path: "MacOS").appending(path: "Trusted")
        try "tampered".write(to: executableURL, atomically: true, encoding: .utf8)

        XCTAssertEqual(TrustManager.shared.checkStatus(path: appURL.path), .tampered)
    }

    func testCheckStatus_AppBundleMissingFingerprintIsNotTrustedByNilEquality() throws {
        let appURL = try makeTestAppBundle()
        defer { try? FileManager.default.removeItem(at: appURL.deletingLastPathComponent()) }

        let entry = TrustEntry(
            kind: .appBundle,
            path: appURL.path,
            fingerprint: nil,
            updatePolicy: .strict
        )
        _ = TrustManager.shared.authorize(entry)

        XCTAssertEqual(TrustManager.shared.checkStatus(path: appURL.path), .tampered)
    }

    func testTrustPathScope_RemovableVolumePrefersVolumeUUIDOverStoredMountPath() {
        let entry = TrustEntry(
            kind: .removableVolume,
            path: "/Volumes/OldName",
            volumeUUID: "VOL-1234"
        )

        XCTAssertTrue(
            TrustPathScope.matches(
                entry,
                queriedPath: "/Volumes/NewName/tool.sh",
                queriedVolumeUUID: "VOL-1234"
            )
        )
        XCTAssertFalse(
            TrustPathScope.matches(
                entry,
                queriedPath: "/Volumes/NewName/tool.sh",
                queriedVolumeUUID: "VOL-9999"
            )
        )
    }

    func testCheckStatus_RemovableVolumeTrust_DoesNotRequireFingerprint() {
        _ = TrustManager.shared.authorize(
            TrustEntry(kind: .removableVolume, path: "/Volumes/TestVolume")
        )

        XCTAssertEqual(TrustManager.shared.checkStatus(path: "/Volumes/TestVolume/tool"), .trusted)
    }

    func testTrustStore_RecoversFromBackupWhenPrimaryIsCorrupted() throws {
        let trustedPath = tempRoot.appendingPathComponent("trusted.txt")
        try "original".write(to: trustedPath, atomically: true, encoding: .utf8)

        XCTAssertTrue(
            TrustManager.shared.authorize(
                TrustEntry(
                    kind: .exactPath,
                    path: trustedPath.path,
                    fingerprint: FileHasher.sha512(at: trustedPath)
                )
            )
        )

        try Data("corrupt".utf8).write(to: TrustStorePath.url, options: .atomic)

        TrustManager.shared.reset()
        TrustManager.shared.initialize()

        XCTAssertTrue(TrustManager.shared.isTrusted(path: trustedPath.path))
        XCTAssertTrue(FileManager.default.fileExists(atPath: TrustStorePath.backupURL.path))
    }

    func testTrustValidator_RejectsNonRegularFilesAndInsecurePermissions() throws {
        let fifoURL = tempRoot.appendingPathComponent("pipe")
        let result = mkfifo(fifoURL.path, 0o600)
        XCTAssertEqual(result, 0)

        switch TrustValidator.validate(fifoURL.path) {
        case .failure(.unsupportedFileType):
            break
        default:
            XCTFail("Expected unsupported file type failure")
        }

        let writableURL = tempRoot.appendingPathComponent("world-writable")
        try "data".write(to: writableURL, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o666], ofItemAtPath: writableURL.path)

        switch TrustValidator.validate(writableURL.path) {
        case .failure(.insecurePermissions):
            break
        default:
            XCTFail("Expected insecure permissions failure")
        }
    }

    private func makeTestAppBundle() throws -> URL {
        let rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        let appURL = rootURL.appendingPathComponent("Trusted.app")
        let contentsURL = appURL.appending(path: "Contents")
        let macOSURL = contentsURL.appending(path: "MacOS")
        try FileManager.default.createDirectory(at: macOSURL, withIntermediateDirectories: true)

        let infoPlist: [String: Any] = [
            "CFBundleIdentifier": "com.example.trusted",
            "CFBundleExecutable": "Trusted",
            "CFBundlePackageType": "APPL"
        ]
        let plistData = try PropertyListSerialization.data(fromPropertyList: infoPlist, format: .xml, options: 0)
        try plistData.write(to: contentsURL.appending(path: "Info.plist"), options: .atomic)
        try "original".write(to: macOSURL.appending(path: "Trusted"), atomically: true, encoding: .utf8)

        return appURL
    }
}
