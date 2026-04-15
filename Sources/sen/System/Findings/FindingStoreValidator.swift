import Foundation

enum FindingStoreValidator {
    static func validate(_ findings: [String: FindingRecord]) throws -> [String: FindingRecord] {
        var validated: [String: FindingRecord] = [:]

        for (key, record) in findings {
            guard !key.isEmpty else {
                throw ValidationError.invalidIdentifier
            }
            guard record.id == key else {
                throw ValidationError.identifierMismatch
            }
            guard record.count >= 1 else {
                throw ValidationError.invalidCount
            }
            guard record.lastSeen >= record.firstSeen else {
                throw ValidationError.invalidTimestamps
            }
            if let lastAlertedAt = record.lastAlertedAt, lastAlertedAt < record.firstSeen {
                throw ValidationError.invalidAlertTimestamp
            }

            validated[key] = record
        }

        return validated
    }

    enum ValidationError: Error {
        case invalidIdentifier
        case identifierMismatch
        case invalidCount
        case invalidTimestamps
        case invalidAlertTimestamp
    }
}
