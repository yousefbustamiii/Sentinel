import Foundation

enum NetworkListenerHeuristics {
    private static let suspiciousPorts: Set<Int> = [1337, 4444, 31337]
    private static let developmentPorts: Set<Int> = [
        3000, 3001, 4200, 5000, 5173, 5432, 6379, 8000, 8080, 8081, 8888, 9000
    ]

    private static let developmentProcessMarkers = [
        "node", "npm", "pnpm", "yarn", "bun", "vite", "next", "webpack",
        "python", "uvicorn", "gunicorn", "ruby", "rails", "java", "gradle",
        "postgres", "redis", "docker", "orbstack", "colima", "code", "cursor"
    ]

    static func shouldIgnore(listener: NetworkListenerSnapshot, executablePath: String?) -> Bool {
        if listener.isLocalOnly,
           executablePath != nil,
           developmentPorts.contains(listener.endpointPort),
           isDevelopmentProcessFamily(listener.processName),
           !suspiciousPorts.contains(listener.endpointPort) {
            return true
        }

        return false
    }

    static func hasMeaningfulNetworkSignal(
        listener: NetworkListenerSnapshot,
        hasExecutablePath: Bool,
        isRecurring: Bool,
        isSignatureValid: Bool
    ) -> Bool {
        if suspiciousPorts.contains(listener.endpointPort) && !listener.isLocalOnly {
            return true
        }

        if suspiciousPorts.contains(listener.endpointPort) && !isSignatureValid {
            return true
        }

        if !hasExecutablePath {
            return !listener.isLocalOnly && !isSignatureValid
        }

        return !isRecurring || !listener.isLocalOnly
    }

    static func isDevelopmentProcessFamily(_ processName: String) -> Bool {
        let normalized = processName.lowercased()
        return developmentProcessMarkers.contains(where: { normalized.contains($0) })
    }
}
