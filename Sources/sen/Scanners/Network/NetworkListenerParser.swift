import Foundation

enum NetworkListenerParser {
    private struct PartialProcess {
        var pid: Int32?
        var command: String?
        var userID: Int?
    }

    private struct PartialFile {
        var name: String?
    }

    static func parse(_ output: String) -> [NetworkListenerSnapshot] {
        var listeners: [NetworkListenerSnapshot] = []
        var process = PartialProcess()
        var file = PartialFile()

        func flushFile() {
            guard let pid = process.pid,
                  let command = process.command,
                  let name = file.name,
                  let endpoint = parseEndpoint(name),
                  endpoint.port > 0 else {
                file = PartialFile()
                return
            }

            listeners.append(NetworkListenerSnapshot(
                processIdentifier: pid,
                processName: command,
                userID: process.userID,
                userName: NetworkProcessInfoResolver.userName(for: process.userID),
                endpointHost: endpoint.host,
                endpointPort: endpoint.port,
                isLocalOnly: endpoint.isLocalOnly
            ))
            file = PartialFile()
        }

        func flushProcess() {
            flushFile()
            process = PartialProcess()
        }

        for rawLine in output.split(separator: "\n", omittingEmptySubsequences: false) {
            guard let field = rawLine.first else { continue }
            let value = String(rawLine.dropFirst())

            switch field {
            case "p":
                flushProcess()
                process.pid = Int32(value)
            case "c":
                process.command = value
            case "u":
                process.userID = Int(value)
            case "f":
                flushFile()
            case "n":
                file.name = value
            default:
                continue
            }
        }

        flushProcess()
        return listeners
    }

    private static func parseEndpoint(_ value: String) -> (host: String, port: Int, isLocalOnly: Bool)? {
        let endpoint = value.split(separator: "->").first.map(String.init) ?? value
        let trimmed = endpoint.trimmingCharacters(in: .whitespacesAndNewlines)

        guard let colonIndex = trimmed.lastIndex(of: ":") else { return nil }
        let host = String(trimmed[..<colonIndex]).trimmingCharacters(in: .whitespacesAndNewlines)
        let portValue = String(trimmed[trimmed.index(after: colonIndex)...])
        guard let port = Int(portValue.filter(\.isNumber)) else { return nil }

        return (
            host: host,
            port: port,
            isLocalOnly: isLoopbackHost(host)
        )
    }

    private static func isLoopbackHost(_ host: String) -> Bool {
        let normalized = host.lowercased()
        return normalized == "127.0.0.1" ||
            normalized == "localhost" ||
            normalized == "::1" ||
            normalized == "[::1]"
    }
}
