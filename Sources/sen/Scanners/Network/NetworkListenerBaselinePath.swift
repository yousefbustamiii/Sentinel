import Foundation

enum NetworkListenerBaselinePath {
    static var url: URL {
        Configuration.shared.rootDirectory.appending(path: "network_listener_baseline.json")
    }
}
