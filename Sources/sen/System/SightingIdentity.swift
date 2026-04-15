import Foundation

/// Formalizes the unique identity of a security sighting to ensure consistent persistence keys.
public struct SightingIdentity {
    private let rawValue: String
    
    public init(category: String, name: String, path: String?, uniqueID: String? = nil) {
        let components = [category, name, path ?? "nil", uniqueID ?? "nil"]
        self.rawValue = components.joined(separator: "||")
    }
    
    /// Returns the unique base64 encoded identifier for this sighting.
    public var uniqueID: String {
        Data(rawValue.utf8).base64EncodedString()
    }
}
