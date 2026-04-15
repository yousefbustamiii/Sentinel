import Darwin
import Foundation

enum LogStoreWriter {
    private static let logEncoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        return encoder
    }()

    static func append(_ entry: LogEntry, to url: URL) throws {
        var data = try logEncoder.encode(entry)
        data.append(0x0A)

        let descriptor = open(url.path, O_WRONLY | O_APPEND | O_CREAT, S_IRUSR | S_IWUSR)
        guard descriptor >= 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { close(descriptor) }

        guard flock(descriptor, LOCK_EX) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        defer { flock(descriptor, LOCK_UN) }

        try data.withUnsafeBytes { rawBuffer in
            guard let baseAddress = rawBuffer.baseAddress else { return }
            let bytesWritten = write(descriptor, baseAddress, rawBuffer.count)
            guard bytesWritten == rawBuffer.count else {
                throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
            }
        }

        if fsync(descriptor) != 0 {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }

        hardenPermissions(at: url)
    }

    static func hardenPermissions(at url: URL) {
        try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
    }
}
