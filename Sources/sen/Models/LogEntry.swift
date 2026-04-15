import Foundation

/// Represents a standardized log entry for forensics and reporting.
public struct LogEntry: Codable {
    public struct Timestamp: Codable {
        public let isoUtc: String
        public let timeReadable: String
        
        enum CodingKeys: String, CodingKey {
            case isoUtc = "iso_utc"
            case timeReadable = "time_readable"
        }
    }

    public struct Extra: Codable {
        public let toolName: String
        public let message: String
        public let severity: LogSeverity
        public let category: String?
        public let evidence: [Evidence]?
        
        enum CodingKeys: String, CodingKey {
            case toolName = "tool_name"
            case message
            case severity
            case category
            case evidence
        }
        
        public init(toolName: String, message: String, severity: LogSeverity, category: String? = nil, evidence: [Evidence]? = nil) {
            self.toolName = toolName
            self.message = message
            self.severity = severity
            self.category = category
            self.evidence = evidence
        }
    }

    public let eventName: String
    public let timestamp: Timestamp
    public let extra: Extra
    
    enum CodingKeys: String, CodingKey {
        case eventName = "event_name"
        case timestamp
        case extra
    }

    public init(eventName: String, toolName: String, severity: LogSeverity, message: String, category: String? = nil, evidence: [Evidence]? = nil) {
        self.eventName = eventName
        self.timestamp = LogEntry.generateTimestamp()
        self.extra = Extra(
            toolName: toolName, 
            message: message,
            severity: severity, 
            category: category, 
            evidence: evidence
        )
    }

    private static func generateTimestamp() -> Timestamp {
        let now = Date()
        let isoFormatter = ISO8601DateFormatter()
        let timeFormatter = DateFormatter()
        timeFormatter.dateFormat = "h:mm:ss a 'UTC'"
        timeFormatter.timeZone = TimeZone(abbreviation: "UTC")

        return Timestamp(
            isoUtc: isoFormatter.string(from: now),
            timeReadable: timeFormatter.string(from: now)
        )
    }
}
