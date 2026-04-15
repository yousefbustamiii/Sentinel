import Foundation

/// Semantic path provider for the persistence integrity state store.
public struct PersistenceStatePath {
    public static var url: URL {
        Configuration.shared.persistenceStateURL
    }

    public static var backupURL: URL {
        url.deletingPathExtension().appendingPathExtension("json.bak")
    }
}
