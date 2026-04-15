import Foundation
import CommonCrypto

/// Generates cryptographically secure fingerprints for file integrity.
public struct FileHasher {
    
    /// Returns a SHA512 hex string for the file at the given URL using streaming chunks.
    public static func sha512(at url: URL) -> String? {
        guard let fileHandle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? fileHandle.close() }
        
        var context = CC_SHA512_CTX()
        CC_SHA512_Init(&context)
        
        let bufferSize = 65536 // 64kb chunks
        while true {
            let data = fileHandle.readData(ofLength: bufferSize)
            if data.isEmpty { break }
            data.withUnsafeBytes {
                _ = CC_SHA512_Update(&context, $0.baseAddress, CC_LONG(data.count))
            }
        }
        
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA512_DIGEST_LENGTH))
        CC_SHA512_Final(&digest, &context)
        
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
