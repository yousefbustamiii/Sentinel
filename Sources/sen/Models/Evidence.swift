import Foundation

/// Represents a single piece of security evidence with an associated weight.
public struct Evidence: Codable, Equatable {
    
    public enum EvidenceCode: String, Codable {
        // Code Integrity
        case unverifiedIdentity   = "UNVERIFIED_IDENTITY" // SecCode check failed
        case unsignedBinary       = "UNSIGNED_BINARY"     // No signature at all
        
        // Execution Anomalies
        case pathAnomaly          = "PATH_ANOMALY"        // Executing from /tmp, etc.
        case hiddenRootItem       = "HIDDEN_ROOT_ITEM"    // Leading dot at root or home
        case searchPathExecution  = "SEARCH_PATH_EXEC"    // Execution from user-writable search paths
        case dylibInjection       = "DYLIB_INJECTION"     // DYLD markers found
        
        // Behavioral / Heuristic
        case knownToolMatch       = "KNOWN_TOOL_MATCH"    // Name match (ngrok, etc.)
        case anomalousPort        = "ANOMALOUS_PORT"      // Backdoor port listener
        case suspiciousFilename   = "SUSPICIOUS_FILENAME" // payload.sh, stage2.pkg
        
        // Persistence / OS
        case newPersistence       = "NEW_PERSISTENCE"     // LaunchAgent/Daemon entry
        case tamperingDetected    = "TAMPERING_DETECTED"  // Trust fingerprint mismatch
        case suspiciousParent     = "SUSPICIOUS_PARENT"   // Parent is unusual (e.g. orphan)
        
        // Removable Media
        case executableAtRoot     = "EXECUTABLE_AT_ROOT"  // .app/.pkg at USB root
    }

    /// The unique semantic code for this evidence.
    public let code: EvidenceCode
    
    /// A human-readable description of what was observed.
    public let description: String
    
    /// The source scanner that provided this evidence.
    public let source: ScannerSource
    
    /// Optional context metadata (e.g. the specific port number or path).
    public let context: String?
    
    public init(code: EvidenceCode, description: String, source: ScannerSource, context: String? = nil) {
        self.code = code
        self.description = description
        self.source = source
        self.context = context
    }
}
