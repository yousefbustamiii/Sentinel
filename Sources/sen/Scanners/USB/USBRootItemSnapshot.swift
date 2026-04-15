import Foundation

struct USBRootItemSnapshot {
    let name: String
    let lowercasedName: String
    let pathExtension: String

    init(name: String) {
        self.name = name
        self.lowercasedName = name.lowercased()
        self.pathExtension = (name as NSString).pathExtension.lowercased()
    }

    var isHidden: Bool {
        name.hasPrefix(".")
    }

    var isBundleOrDiskImageAtRoot: Bool {
        USBContentRules.bundleExtensions.contains(pathExtension)
    }

    var isScriptAtRoot: Bool {
        USBContentRules.scriptExtensions.contains(pathExtension)
    }

    var isExecutableLikeAtRoot: Bool {
        isBundleOrDiskImageAtRoot || isScriptAtRoot
    }
}
