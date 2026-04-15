import Foundation

enum USBVolumeIdentity {
    static func sightingIdentity(for url: URL) -> String {
        url.volumeUUID ?? url.path
    }
}
