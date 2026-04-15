import Foundation

internal enum PasswordPolicy {
    static let minimumLength = 8
    static let maximumLength = 64

    static func validate(_ password: String) -> String? {
        guard password.count >= minimumLength else {
            return "Password must be at least \(minimumLength) characters."
        }

        guard password.count <= maximumLength else {
            return "Password must be at most \(maximumLength) characters."
        }

        guard !password.contains(where: \.isWhitespace) else {
            return "Password cannot contain spaces or whitespace."
        }

        return nil
    }
}
