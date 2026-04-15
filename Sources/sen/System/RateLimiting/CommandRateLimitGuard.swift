import Foundation

internal enum CommandRateLimitGuard {
    static func enforce(_ action: CommandRateLimitedAction) -> Bool {
        let decision = CommandRateLimiter.shared.acquire(action)
        guard !decision.allowed else { return true }

        let retryAfter = Int(ceil(decision.retryAfter ?? action.windowDuration))
        TerminalUI.space()
        TerminalUI.printSingle("\(action.denialMessage) \(retryAfter)s.", style: .error)
        TerminalUI.space()
        return false
    }
}
