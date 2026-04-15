import Foundation

enum LogStoreReader {
    static func readEntries(from url: URL) -> [LogEntry] {
        guard let data = try? Data(contentsOf: url),
              let content = String(data: data, encoding: .utf8) else {
            return []
        }

        let completeLines = completeJSONLines(from: content)
        return completeLines.compactMap { line in
            try? StorageUtils.decoder.decode(LogEntry.self, from: Data(line.utf8))
        }
    }

    private static func completeJSONLines(from content: String) -> [Substring] {
        let hasTrailingNewline = content.last == "\n"
        var lines = content.split(separator: "\n", omittingEmptySubsequences: true)

        if !hasTrailingNewline, !lines.isEmpty {
            lines.removeLast()
        }

        return lines
    }
}
