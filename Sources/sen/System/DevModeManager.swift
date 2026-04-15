import Foundation

/// Central authority for Developer Mode lifecycle management.
public final class DevModeManager {

    public static let shared = DevModeManager()
    private init() {}

    private let queue = DispatchQueue(label: "com.sentinel.devmode", qos: .utility)

    private var storageURL: URL {
        Configuration.shared.rootDirectory.appending(path: "devmode.json")
    }

    // MARK: - Public API

    /// True when Developer Mode is enabled and its time window has not expired.
    public func isActive() -> Bool {
        queue.sync { load()?.isLive ?? false }
    }

    /// Returns the current state, or nil if inactive / expired.
    public func currentState() -> DevModeState? {
        queue.sync {
            guard let state = load(), state.isLive else { return nil }
            return state
        }
    }

    /// Activates Developer Mode for the given duration.
    public func enable(duration: DevModeState.Duration) {
        queue.sync {
            let state = DevModeState(duration: duration)
            save(state)
        }
    }

    /// Permanently deactivates Developer Mode.
    public func disable() {
        queue.sync {
            try? FileManager.default.removeItem(at: storageURL)
        }
    }

    // MARK: - Private

    private func load() -> DevModeState? {
        guard let data = try? Data(contentsOf: storageURL) else { return nil }
        return try? StorageUtils.decoder.decode(DevModeState.self, from: data)
    }

    private func save(_ state: DevModeState) {
        StorageUtils.ensureDirectoryExists(for: storageURL)
        guard let data = try? StorageUtils.encoder.encode(state) else { return }
        try? data.write(to: storageURL, options: .atomic)
    }
}
