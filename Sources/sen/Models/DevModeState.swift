import Foundation

/// Represents the persisted state of Developer Mode.
public struct DevModeState: Codable {

    /// The mode of activation — bounded by time or perpetually active.
    public enum Duration: Codable {
        case timed(until: Date)
        case unlimited
    }

    public let enabledAt: Date
    public let duration: Duration

    enum CodingKeys: String, CodingKey {
        case enabledAt  = "enabled_at"
        case duration
        case expiresAt  = "expires_at"
        case isUnlimited = "is_unlimited"
    }

    public init(duration: Duration) {
        self.enabledAt = Date()
        self.duration  = duration
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabledAt  = try c.decode(Date.self, forKey: .enabledAt)
        let unlimited = try c.decodeIfPresent(Bool.self, forKey: .isUnlimited) ?? false
        if unlimited {
            duration = .unlimited
        } else {
            let exp = try c.decode(Date.self, forKey: .expiresAt)
            duration = .timed(until: exp)
        }
    }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(enabledAt, forKey: .enabledAt)
        switch duration {
        case .timed(let exp):
            try c.encode(exp,  forKey: .expiresAt)
            try c.encode(false, forKey: .isUnlimited)
        case .unlimited:
            try c.encode(true, forKey: .isUnlimited)
        }
    }

    /// True when this state has not yet expired.
    public var isLive: Bool {
        switch duration {
        case .unlimited:          return true
        case .timed(let exp):     return Date() < exp
        }
    }

    /// Human-readable description of the remaining window.
    public var remainingDescription: String {
        switch duration {
        case .unlimited:
            return "unlimited — active until manually deactivated"
        case .timed(let exp):
            let remaining = max(0, exp.timeIntervalSince(Date()))
            let days  = Int(remaining / 86_400)
            let hours = Int((remaining.truncatingRemainder(dividingBy: 86_400)) / 3_600)
            if days > 0 {
                return "\(days)d \(hours)h remaining"
            } else {
                return "\(hours)h remaining"
            }
        }
    }
}
