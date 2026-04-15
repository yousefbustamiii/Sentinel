import Darwin
import Foundation

/// Errors that can occur during trust path validation.
public enum TrustValidationError: Error {
    case nonExistent
    case relativePath
    case blockedPath(reason: String)
    case directoryNotAllowed
    case gibberish
    case linkResolvesToBlocked(target: String)
    case unsupportedFileType(reason: String)
    case insecurePermissions(reason: String)
    case suspiciousOwnership(reason: String)

    public var description: String {
        switch self {
        case .nonExistent:
            return "The specified path does not exist on disk."
        case .relativePath:
            return "Relative paths are not allowed. Please use an absolute path."
        case .blockedPath(let reason):
            return "Path blocked: \(reason)"
        case .directoryNotAllowed:
            return "Trusting entire directories is not allowed for security reasons. Please trust a specific file or .app bundle."
        case .gibberish:
            return "The input does not look like a valid path structure."
        case .linkResolvesToBlocked(let target):
            return "This link resolves to a blocked location: \(target)"
        case .unsupportedFileType(let reason):
            return "Unsupported file type: \(reason)"
        case .insecurePermissions(let reason):
            return "Insecure permissions: \(reason)"
        case .suspiciousOwnership(let reason):
            return "Suspicious ownership: \(reason)"
        }
    }
}

/// Specialized logic to ensure users only trust narrow, specific, and non-volatile locations.
public struct TrustValidator {
    
    /// Validates and canonicalizes a path string.
    public static func validate(_ input: String) -> Result<URL, TrustValidationError> {
        // 1. Basic syntax / gibberish check
        guard input.contains("/") || input.starts(with: "~") else {
            return .failure(.gibberish)
        }
        
        // 2. Expand tilde and fully resolve all components (including symlinks)
        let expanded = (input as NSString).expandingTildeInPath
        let url = URL(fileURLWithPath: expanded).standardized.resolvingSymlinksInPath()
        let path = url.path
        
        // 3. Absolute path enforcement
        guard path.starts(with: "/") else {
            return .failure(.relativePath)
        }
        
        // 4. Existence check
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: path, isDirectory: &isDir) else {
            return .failure(.nonExistent)
        }

        let attributes = try? FileManager.default.attributesOfItem(atPath: path)
        
        // 5. Block temporary folders (hard block)
        if path.lowercased().contains("/tmp/") || path.lowercased().hasSuffix("/tmp") {
            return .failure(.blockedPath(reason: "Temporary locations are volatile and cannot be trusted."))
        }
        
        // 6. Block broad root/system folders
        let blockedPrefixes = [
            "/Applications", "/Users", "/Library", "/System", 
            "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/var", "/private"
        ]
        
        // We allow sub-paths in some cases (like App bundles), but the prefixes themselves are blocked.
        for prefix in blockedPrefixes {
            if path == prefix || path == prefix + "/" {
                return .failure(.blockedPath(reason: "Cannot trust a core system directory."))
            }
        }
        
        // Check if it's a broad user home path (e.g. /Users/yousef)
        let home = NSHomeDirectory()
        if path == home || path == home + "/" {
            return .failure(.blockedPath(reason: "Cannot trust your entire home directory."))
        }
        
        // 7. Directory check (Apps are allowed as specialized directories)
        if isDir.boolValue {
            if !path.hasSuffix(".app") && !isRemovableVolumeRoot(path) {
                return .failure(.directoryNotAllowed)
            }
        } else if let fileType = attributes?[.type] as? FileAttributeType, fileType != .typeRegular {
            return .failure(.unsupportedFileType(reason: "Only regular files, .app bundles, and removable volume roots can be trusted."))
        }

        if !isRemovableVolumePath(path) {
            if hasWritableByOthersPermissions(attributes) {
                return .failure(.insecurePermissions(reason: "Path is writable by group or others."))
            }

            if hasSuspiciousOwnership(attributes) {
                return .failure(.suspiciousOwnership(reason: "Path is not owned by root or the current user."))
            }
        }
        
        return .success(url)
    }

    private static func isRemovableVolumeRoot(_ path: String) -> Bool {
        let components = URL(fileURLWithPath: path).pathComponents
        return components.count == 3 && components[1] == "Volumes"
    }

    private static func isRemovableVolumePath(_ path: String) -> Bool {
        let components = URL(fileURLWithPath: path).pathComponents
        return components.count >= 3 && components[1] == "Volumes"
    }

    private static func hasWritableByOthersPermissions(_ attributes: [FileAttributeKey: Any]?) -> Bool {
        guard let permissions = attributes?[.posixPermissions] as? NSNumber else {
            return true
        }

        let mode = permissions.uint16Value
        return (mode & 0o002) != 0 || (mode & 0o020) != 0
    }

    private static func hasSuspiciousOwnership(_ attributes: [FileAttributeKey: Any]?) -> Bool {
        guard let ownerUserID = attributes?[.ownerAccountID] as? Int else {
            return true
        }

        let currentUserID = Int(getuid())
        return ownerUserID != 0 && ownerUserID != currentUserID
    }
}
