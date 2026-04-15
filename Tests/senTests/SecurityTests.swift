import XCTest
@testable import sen

final class SecurityTests: XCTestCase {
    func testPasswordHasher_UsesVersionedFormatAndVerifies() throws {
        let password = "verysecurepassword"
        let stored = try XCTUnwrap(PasswordHasher.hash(password))

        XCTAssertTrue(stored.hasPrefix("scrypt:"))
        XCTAssertTrue(PasswordHasher.isValidStoredRepresentation(stored))
        XCTAssertNotNil(PasswordHasher.parseStoredHash(stored))
        XCTAssertTrue(PasswordHasher.verify(password, against: stored))
        XCTAssertFalse(PasswordHasher.verify("wrongpassword", against: stored))
    }

    func testPasswordHasher_InvalidStoredRepresentation_IsRejected() {
        XCTAssertFalse(PasswordHasher.isValidStoredRepresentation("garbage"))
        XCTAssertFalse(AuthenticationService.isStoredPasswordValid("garbage"))
        XCTAssertNil(PasswordHasher.parseStoredHash("scrypt:N=bad:r=8:p=1:salt:key"))
        XCTAssertNil(PasswordHasher.parseStoredHash("scrypt:N=16384:r=8:p=1:c2FsdA==:a2V5"))
    }
}
