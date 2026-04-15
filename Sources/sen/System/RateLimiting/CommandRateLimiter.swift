import Foundation

internal struct CommandRateLimitDecision {
    let allowed: Bool
    let retryAfter: TimeInterval?
}

internal enum CommandRateLimitedAction: String, Codable, CaseIterable {
    case dev
    case logs
    case run
    case status
    case stop
    case passwordChange
    case trust

    var maximumAttempts: Int {
        switch self {
        case .run, .stop:
            return 10
        case .passwordChange:
            return 2
        case .trust, .dev:
            return 5
        case .logs, .status:
            return 30
        }
    }

    var windowDuration: TimeInterval {
        30
    }

    var denialMessage: String {
        switch self {
        case .dev:
            return "Developer mode command rate limit reached. Try again in"
        case .logs:
            return "Logs command rate limit reached. Try again in"
        case .run:
            return "Run command rate limit reached. Try again in"
        case .status:
            return "Status command rate limit reached. Try again in"
        case .stop:
            return "Stop command rate limit reached. Try again in"
        case .passwordChange:
            return "Password change rate limit reached. Try again in"
        case .trust:
            return "Trust command rate limit reached. Try again in"
        }
    }
}

internal final class CommandRateLimiter {
    static let shared = CommandRateLimiter()

    private struct Entry: Codable {
        var windowStart: Date
        var count: Int
    }

    private let queue = DispatchQueue(label: "com.sentinel.commandratelimiter", qos: .userInitiated)

    private init() {}

    func acquire(_ action: CommandRateLimitedAction, now: Date = Date()) -> CommandRateLimitDecision {
        queue.sync {
            var state = loadState()
            pruneExpiredEntries(from: &state, now: now)

            var entry = state[action] ?? Entry(windowStart: now, count: 0)
            let windowEnd = entry.windowStart.addingTimeInterval(action.windowDuration)
            if now >= windowEnd {
                entry = Entry(windowStart: now, count: 0)
            }

            guard entry.count < action.maximumAttempts else {
                let retryAfter = max(0, windowEnd.timeIntervalSince(now))
                persist(state)
                return CommandRateLimitDecision(allowed: false, retryAfter: retryAfter)
            }

            entry.count += 1
            state[action] = entry
            persist(state)
            return CommandRateLimitDecision(allowed: true, retryAfter: nil)
        }
    }

    #if DEBUG
    func reset() {
        queue.sync {
            try? FileManager.default.removeItem(at: CommandRateLimitPath.url)
        }
    }
    #endif

    private func loadState() -> [CommandRateLimitedAction: Entry] {
        guard
            let data = try? Data(contentsOf: CommandRateLimitPath.url),
            let decoded = try? StorageUtils.decoder.decode([CommandRateLimitedAction: Entry].self, from: data)
        else {
            return [:]
        }

        return Dictionary(
            uniqueKeysWithValues: decoded.filter { CommandRateLimitedAction.allCases.contains($0.key) }
        )
    }

    private func persist(_ state: [CommandRateLimitedAction: Entry]) {
        do {
            StorageUtils.ensureDirectoryExists(for: CommandRateLimitPath.url)
            let data = try StorageUtils.encoder.encode(state)
            try data.write(to: CommandRateLimitPath.url, options: .atomic)
            try? FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: CommandRateLimitPath.url.path)
        } catch {
            return
        }
    }

    private func pruneExpiredEntries(from state: inout [CommandRateLimitedAction: Entry], now: Date) {
        for action in CommandRateLimitedAction.allCases {
            guard let entry = state[action] else { continue }
            if now.timeIntervalSince(entry.windowStart) >= action.windowDuration {
                state.removeValue(forKey: action)
            }
        }
    }
}
