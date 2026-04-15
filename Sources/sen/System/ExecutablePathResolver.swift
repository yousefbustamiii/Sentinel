import Darwin
import Foundation

enum ExecutablePathResolver {
    static func currentExecutablePath() -> String? {
        if let bundleExecutablePath = Bundle.main.executablePath,
           !bundleExecutablePath.isEmpty,
           FileManager.default.fileExists(atPath: bundleExecutablePath) {
            return bundleExecutablePath
        }

        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let length = proc_pidpath(getpid(), &buffer, UInt32(buffer.count))
        guard length > 0 else { return nil }

        let path = String(cString: buffer)
        return FileManager.default.fileExists(atPath: path) ? path : nil
    }
}
