import Foundation
import Security

/// High-level wrapper for macOS SecCode APIs to extract identity and signing metadata.
public struct CodeSignatureService {
    
    public struct Identity {
        public let bundleID: String?
        public let teamID: String?
        public let uniqueID: String? // CDHash unique identifier
        public let isAppleSigned: Bool
    }
    
    /// Extracts the bundle and team identity for a given file URL.
    public static func getIdentity(for url: URL) -> Identity {
        var staticCode: SecStaticCode?
        let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        
        guard createStatus == errSecSuccess, let code = staticCode else {
            return Identity(bundleID: nil, teamID: nil, uniqueID: nil, isAppleSigned: false)
        }
        
        var signingInfo: CFDictionary?
        let infoStatus = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &signingInfo)
        
        guard infoStatus == errSecSuccess, let info = signingInfo as? [String: Any] else {
            return Identity(bundleID: nil, teamID: nil, uniqueID: nil, isAppleSigned: false)
        }
        
        let bundleID = info[kSecCodeInfoIdentifier as String] as? String
        var teamID = info[kSecCodeInfoTeamIdentifier as String] as? String
        
        if teamID == nil, let ents = info[kSecCodeInfoEntitlements as String] as? [String: Any] {
            teamID = ents["com.apple.developer.team-identifier"] as? String
        }

        let isApple = isSignedByApple(code) ||
            teamID == "Apple" ||
            (teamID == nil && bundleID?.starts(with: "com.apple.") == true)
        
        // Extract CDHash (Unique Identifier)
        let uniqueID = info[kSecCodeInfoUnique as String] as? Data

        return Identity(
            bundleID: bundleID, 
            teamID: teamID, 
            uniqueID: uniqueID?.base64EncodedString(),
            isAppleSigned: isApple
        )
    }

    /// Returns true if the process fails native cryptographic validity checks.
    public static func isUnverified(pid: Int32) -> Bool {
        var code: SecCode?
        let attributes = [kSecGuestAttributePid: pid] as CFDictionary
        let status = SecCodeCopyGuestWithAttributes(nil, attributes, [], &code)
        guard status == errSecSuccess, let secCode = code else { return true }
        
        // SecCodeCheckValidity verifies that the code matches its signature and 
        // that the signature is trusted per system policy.
        return SecCodeCheckValidity(secCode, [], nil) != errSecSuccess
    }

    /// Returns true if the binary at the given path fails native signature validation.
    public static func isUnverified(at path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        var staticCode: SecStaticCode?
        let status = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard status == errSecSuccess, let code = staticCode else { return true }
        return SecStaticCodeCheckValidity(code, [], nil) != errSecSuccess
    }

    /// Returns true if the binary is specifically signed by Apple.
    public static func isAppleSigned(at path: String) -> Bool {
        let identity = getIdentity(for: URL(fileURLWithPath: path))
        return identity.isAppleSigned
    }

    private static func isSignedByApple(_ code: SecStaticCode) -> Bool {
        var requirement: SecRequirement?
        let status = SecRequirementCreateWithString("anchor apple generic" as CFString, [], &requirement)
        guard status == errSecSuccess, let requirement else { return false }
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSBasicValidateOnly), requirement) == errSecSuccess
    }
}
