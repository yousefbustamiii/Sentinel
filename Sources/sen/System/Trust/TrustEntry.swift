import Foundation

/// The nature of the trust granted to a path.
public enum TrustKind: String, Codable {
    case exactPath       = "EXACT_PATH"
    case exactFile       = "EXACT_FILE"
    case appBundle       = "APP_BUNDLE"
    case signer          = "SIGNER"
    case developer       = "DEVELOPER"
    case ecosystem       = "ECOSYSTEM"
    case removableVolume = "REMOVABLE_VOLUME"
}

/// Policy for handling updates to a trusted entity.
public enum UpdatePolicy: String, Codable {
    case strict
    case allowSignedUpdates
}

/// The verification status of a path against the trust store.
public enum TrustStatus: String, Codable {
    case trusted   = "TRUSTED"
    case tampered  = "TAMPERED"
    case untrusted = "UNTRUSTED"
}

/// Represents a user-trusted entity with multi-factor identity markers.
public struct TrustEntry: Codable, Equatable {
    public let kind: TrustKind
    public let path: String
    public let fingerprint: String?
    public let volumeUUID: String?
    public let bundleID: String?
    public let teamID: String?
    public let provenance: String?
    public let resolvedPath: String?
    public let fileType: String?
    public let ownerUserID: Int?
    public let ownerGroupID: Int?
    public let updatePolicy: UpdatePolicy
    public let createdAt: Date
    
    public init(
        kind: TrustKind,
        path: String,
        fingerprint: String? = nil,
        volumeUUID: String? = nil,
        bundleID: String? = nil,
        teamID: String? = nil,
        provenance: String? = nil,
        resolvedPath: String? = nil,
        fileType: String? = nil,
        ownerUserID: Int? = nil,
        ownerGroupID: Int? = nil,
        updatePolicy: UpdatePolicy = .strict,
        createdAt: Date = Date()
    ) {
        self.kind = kind
        self.path = path
        self.fingerprint = fingerprint
        self.volumeUUID = volumeUUID
        self.bundleID = bundleID
        self.teamID = teamID
        self.provenance = provenance
        self.resolvedPath = resolvedPath
        self.fileType = fileType
        self.ownerUserID = ownerUserID
        self.ownerGroupID = ownerGroupID
        self.updatePolicy = updatePolicy
        self.createdAt = createdAt
    }
}

internal extension TrustKind {
    var isExactPathScope: Bool {
        self == .exactPath || self == .exactFile
    }

    var isSignerScope: Bool {
        self == .signer || self == .developer
    }

    var isEcosystemScope: Bool {
        self == .ecosystem || self == .removableVolume
    }

    var isExactMatchScope: Bool {
        isExactPathScope || self == .ecosystem
    }

    var requiresPathFingerprint: Bool {
        self == .exactPath || self == .exactFile || self == .appBundle || self == .ecosystem
    }

    var permitsPathTrustWithoutFingerprint: Bool {
        self == .removableVolume
    }

    var displayName: String {
        switch self {
        case .exactPath, .exactFile:
            return "EXACT_PATH"
        case .appBundle:
            return "APP_BUNDLE"
        case .signer, .developer:
            return "SIGNER"
        case .ecosystem:
            return "ECOSYSTEM"
        case .removableVolume:
            return "REMOVABLE_VOLUME"
        }
    }
}
