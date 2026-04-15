import Foundation

struct NetworkListenerSnapshot {
    let processIdentifier: Int32
    let processName: String
    let userID: Int?
    let userName: String?
    let endpointHost: String
    let endpointPort: Int
    let isLocalOnly: Bool

    var listenerIdentity: String {
        [
            userID.map(String.init) ?? "unknown",
            processName.lowercased(),
            endpointHost.lowercased(),
            String(endpointPort)
        ].joined(separator: "|")
    }
}
