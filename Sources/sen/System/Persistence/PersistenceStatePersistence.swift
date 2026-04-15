import Foundation

enum PersistenceStatePersistence {
    static func write(_ state: Data, to url: URL) throws {
        try StorageUtils.writeAtomically(state, to: url)
    }

    static func persist(_ state: Data) throws {
        try write(state, to: PersistenceStatePath.backupURL)
        try write(state, to: PersistenceStatePath.url)
    }
}
