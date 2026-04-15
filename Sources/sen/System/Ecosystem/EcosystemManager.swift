import Foundation

/// Manages the explicit hydration of developer ecosystem binaries into the trust store.
public final class EcosystemManager {
    public struct HydrationReport {
        public let addedEntries: Int
        public let skippedEntries: Int
    }

    struct Candidate {
        let path: String
        let fingerprint: String
        let bundleID: String?
        let teamID: String?
        let provenance: String
        let fileType: String
        let ownerUserID: Int
        let ownerGroupID: Int
    }

    enum Provenance: String {
        case homebrewArm64 = "HOMEBREW_ARM64"
        case homebrewUsrLocal = "HOMEBREW_USR_LOCAL"
        case nixProfile = "NIX_PROFILE"

        var scanPath: String {
            switch self {
            case .homebrewArm64:
                return "/opt/homebrew/bin"
            case .homebrewUsrLocal:
                return "/usr/local/bin"
            case .nixProfile:
                return NSHomeDirectory() + "/.nix-profile/bin"
            }
        }
    }

    static let defaultProvenances: [Provenance] = [
        .homebrewArm64,
        .homebrewUsrLocal,
        .nixProfile
    ]
}
