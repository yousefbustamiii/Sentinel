import Foundation

internal struct LaunchctlResult {
    let status: Int32
    let output: String

    var isSuccess: Bool { status == 0 }
}

internal struct LaunchctlClient {
    let bootstrap: (_ domain: String, _ plistPath: String) -> LaunchctlResult
    let bootout: (_ domain: String, _ target: String) -> LaunchctlResult
    let kickstart: (_ serviceTarget: String) -> LaunchctlResult
    let printService: (_ serviceTarget: String) -> LaunchctlResult

    static let live = LaunchctlClient(
        bootstrap: LaunchctlRunner.bootstrap,
        bootout: LaunchctlRunner.bootout,
        kickstart: LaunchctlRunner.kickstart,
        printService: LaunchctlRunner.printService
    )

    func isLoaded(serviceTarget: String) -> Bool {
        printService(serviceTarget).isSuccess
    }
}
