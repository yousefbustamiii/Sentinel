import Foundation
import CommonCrypto

internal enum CommandRateLimitPath {
    static var url: URL {
        Configuration.shared.rootDirectory
            .appending(path: hiddenDirectoryName)
            .appending(path: hiddenFilename)
    }

    private static var hiddenDirectoryName: String {
        ".\(hashedComponent("sentinel.rate-limit.directory").prefix(12))"
    }

    private static var hiddenFilename: String {
        ".\(hashedComponent("sentinel.rate-limit.file")).cache"
    }

    private static func hashedComponent(_ seed: String) -> String {
        let material = [
            Configuration.shared.bundleID,
            Configuration.shared.productName,
            Configuration.shared.keychainService,
            Configuration.shared.keychainAccount,
            seed
        ].joined(separator: "|")

        let bytes = Array(material.utf8)
        var digest = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(bytes, CC_LONG(bytes.count), &digest)
        return digest.map { String(format: "%02x", $0) }.joined()
    }
}
