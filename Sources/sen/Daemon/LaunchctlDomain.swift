import Darwin

internal enum LaunchctlDomain {
    static var user: String {
        "gui/\(getuid())"
    }

    static func serviceTarget(label: String) -> String {
        "\(user)/\(label)"
    }
}
