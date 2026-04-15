import Foundation

internal enum LaunchAgentInstaller {
    static func installExecutable(from sourceURL: URL, to destinationURL: URL) throws {
        let fm = FileManager.default
        guard fm.fileExists(atPath: sourceURL.path) else {
            throw CocoaError(.fileNoSuchFile)
        }

        StorageUtils.ensureDirectoryExists(for: destinationURL)
        let tempURL = stagingURL(for: destinationURL)

        do {
            try fm.copyItem(at: sourceURL, to: tempURL)
            try applyExecutablePermissions(from: sourceURL, to: tempURL)
            try replaceItem(at: destinationURL, with: tempURL)
            try validateRegularFile(at: destinationURL)
        } catch {
            try? fm.removeItem(at: tempURL)
            throw error
        }
    }

    static func writePlist(_ data: Data, to url: URL) throws {
        StorageUtils.ensureDirectoryExists(for: url)
        try data.write(to: url, options: .atomic)
        try? FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
        _ = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
        try validateRegularFile(at: url)
    }

    private static func stagingURL(for destinationURL: URL) -> URL {
        destinationURL
            .deletingLastPathComponent()
            .appendingPathComponent(".\(destinationURL.lastPathComponent).\(UUID().uuidString).tmp")
    }

    private static func replaceItem(at destinationURL: URL, with tempURL: URL) throws {
        let fm = FileManager.default
        if fm.fileExists(atPath: destinationURL.path) {
            _ = try fm.replaceItemAt(destinationURL, withItemAt: tempURL)
        } else {
            try fm.moveItem(at: tempURL, to: destinationURL)
        }
    }

    private static func applyExecutablePermissions(from sourceURL: URL, to targetURL: URL) throws {
        let attributes = try FileManager.default.attributesOfItem(atPath: sourceURL.path)
        let permissions = attributes[.posixPermissions] as? NSNumber ?? 0o755
        try FileManager.default.setAttributes([.posixPermissions: permissions], ofItemAtPath: targetURL.path)
    }

    private static func validateRegularFile(at url: URL) throws {
        let values = try url.resourceValues(forKeys: [.isRegularFileKey, .fileSizeKey])
        guard values.isRegularFile == true else {
            throw CocoaError(.fileReadUnknown)
        }
    }
}
