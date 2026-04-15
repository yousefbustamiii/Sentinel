import Foundation

public extension URL {
    /// Convenience accessor for extracting code signature identity from a file URL.
    var codeIdentity: CodeSignatureService.Identity {
        CodeSignatureService.getIdentity(for: self)
    }

    /// Convenience accessor for specific identity metadata to reduce unpacking noise.
    var teamID: String?   { codeIdentity.teamID }
    var bundleID: String? { codeIdentity.bundleID }
    var uniqueID: String? { codeIdentity.uniqueID }

    /// Extracts the volume UUID if the URL points to a location on a removable volume.
    var volumeUUID: String? {
        (try? resourceValues(forKeys: [.volumeUUIDStringKey]))?.volumeUUIDString
    }
}
