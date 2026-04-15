import Foundation

/// Internal engine for executing system launchctl commands.
internal enum LaunchctlRunner {
    static func bootstrap(domain: String, plistPath: String) -> LaunchctlResult {
        execute(arguments: ["bootstrap", domain, plistPath])
    }

    static func bootout(domain: String, target: String) -> LaunchctlResult {
        execute(arguments: ["bootout", domain, target])
    }

    static func kickstart(serviceTarget: String) -> LaunchctlResult {
        execute(arguments: ["kickstart", "-k", serviceTarget])
    }

    static func printService(serviceTarget: String) -> LaunchctlResult {
        execute(arguments: ["print", serviceTarget])
    }

    private static func execute(arguments: [String]) -> LaunchctlResult {
        let task = Process()
        let pipe = Pipe()

        task.standardOutput = pipe
        task.standardError = pipe
        task.executableURL = URL(fileURLWithPath: "/bin/launchctl")
        task.arguments = arguments

        do {
            let result = try ProcessOutputCapture.execute(task: task, pipes: [pipe])
            let data = result.outputs[0]
            let output = String(data: data, encoding: .utf8) ?? ""
            return LaunchctlResult(status: result.status, output: output)
        } catch {
            return LaunchctlResult(status: -1, output: error.localizedDescription)
        }
    }
}
