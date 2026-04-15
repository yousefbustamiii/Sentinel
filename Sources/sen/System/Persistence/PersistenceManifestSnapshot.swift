import Foundation

struct PersistenceManifestSnapshot: Equatable {
    let path: String
    let fileHash: String?
    let targetPath: String?
    let signerTeamID: String?
    let lastModified: Date?
    let isValidPropertyList: Bool
    let parseError: String?
}
