import Foundation

final class NetworkListenerBaseline {
    private let store: NetworkListenerBaselineStore

    init(store: NetworkListenerBaselineStore = .shared) {
        self.store = store
    }

    func observe(_ listener: NetworkListenerSnapshot) -> Bool {
        store.observe(identity: listener.listenerIdentity)
    }
}
