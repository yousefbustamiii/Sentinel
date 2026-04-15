import AppKit
import Darwin
import Foundation

enum NetworkProcessInfoResolver {
    static func executablePath(for pid: Int32) -> String? {
        var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
        let result = proc_pidpath(pid, &buffer, UInt32(buffer.count))
        guard result > 0 else { return nil }
        return String(cString: buffer)
    }

    static func runningApplication(for pid: Int32) -> NSRunningApplication? {
        NSWorkspace.shared.runningApplications.first { $0.processIdentifier == pid }
    }

    static func userName(for userID: Int?) -> String? {
        guard let userID else { return nil }
        guard let passwd = getpwuid(uid_t(userID)),
              let name = passwd.pointee.pw_name else {
            return nil
        }
        return String(cString: name)
    }
}
