import XCTest
@testable import sen

final class RateLimitingTests: XCTestCase {
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
        CommandRateLimiter.shared.reset()
    }

    override func tearDown() {
        CommandRateLimiter.shared.reset()
        Configuration.shared = originalConfig
        try? FileManager.default.removeItem(at: tempRoot)
        super.tearDown()
    }

    func testCommandRateLimiter_BlocksAfterLimitWithinWindow() {
        for _ in 0..<10 {
            XCTAssertTrue(CommandRateLimiter.shared.acquire(.run).allowed)
        }

        let denied = CommandRateLimiter.shared.acquire(.run)
        XCTAssertFalse(denied.allowed)
        XCTAssertNotNil(denied.retryAfter)
    }

    func testCommandRateLimiter_UsesSeparateBucketsPerAction() {
        XCTAssertTrue(CommandRateLimiter.shared.acquire(.run).allowed)
        XCTAssertTrue(CommandRateLimiter.shared.acquire(.passwordChange).allowed)
        XCTAssertTrue(CommandRateLimiter.shared.acquire(.passwordChange).allowed)
        XCTAssertFalse(CommandRateLimiter.shared.acquire(.passwordChange).allowed)
        XCTAssertTrue(CommandRateLimiter.shared.acquire(.stop).allowed)
        XCTAssertTrue(CommandRateLimiter.shared.acquire(.status).allowed)
        XCTAssertTrue(CommandRateLimiter.shared.acquire(.logs).allowed)
        XCTAssertTrue(CommandRateLimiter.shared.acquire(.trust).allowed)
        XCTAssertTrue(CommandRateLimiter.shared.acquire(.dev).allowed)
    }

    func testCommandRateLimiter_ResetsAfterWindowExpires() {
        let start = Date(timeIntervalSince1970: 100)
        for _ in 0..<2 {
            XCTAssertTrue(CommandRateLimiter.shared.acquire(.passwordChange, now: start).allowed)
        }

        XCTAssertFalse(
            CommandRateLimiter.shared.acquire(.passwordChange, now: start.addingTimeInterval(5)).allowed
        )
        XCTAssertTrue(
            CommandRateLimiter.shared.acquire(.passwordChange, now: start.addingTimeInterval(31)).allowed
        )
    }

    func testPasswordPolicy_RejectsShortAndWhitespacePasswords() {
        XCTAssertEqual(PasswordPolicy.validate("short"), "Password must be at least 8 characters.")
        XCTAssertEqual(PasswordPolicy.validate("abcd efg"), "Password cannot contain spaces or whitespace.")
        XCTAssertEqual(PasswordPolicy.validate(String(repeating: "a", count: 65)), "Password must be at most 64 characters.")
        XCTAssertEqual(PasswordPolicy.validate("abcdefgh"), nil)
    }

    func testCommandRateLimitPath_UsesHiddenObfuscatedFilename() {
        let url = CommandRateLimitPath.url
        XCTAssertFalse(url.lastPathComponent.contains("rate"))
        XCTAssertTrue(url.lastPathComponent.hasPrefix("."))
        XCTAssertTrue(url.deletingLastPathComponent().lastPathComponent.hasPrefix("."))
        XCTAssertNotEqual(url.lastPathComponent, ".cache")
    }

    func testCommandRateLimiter_CorruptedStateFileFallsBackCleanly() throws {
        let url = CommandRateLimitPath.url
        StorageUtils.ensureDirectoryExists(for: url)
        try Data("corrupt".utf8).write(to: url, options: .atomic)

        let result = CommandRateLimiter.shared.acquire(.run)

        XCTAssertTrue(result.allowed)
        let rewritten = try Data(contentsOf: url)
        XCTAssertNoThrow(
            try StorageUtils.decoder.decode([CommandRateLimitedAction: AnyRateLimitEntry].self, from: rewritten)
        )
    }

    func testCommandRateLimiter_PersistsRestrictedPermissions() throws {
        _ = CommandRateLimiter.shared.acquire(.status)

        let attributes = try FileManager.default.attributesOfItem(atPath: CommandRateLimitPath.url.path)
        let permissions = (attributes[.posixPermissions] as? NSNumber)?.intValue

        XCTAssertEqual(permissions, 0o600)
    }
}

private struct AnyRateLimitEntry: Codable {}
