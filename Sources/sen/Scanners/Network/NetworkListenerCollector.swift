import Foundation

enum NetworkListenerCollector {
    struct Result {
        let listeners: [NetworkListenerSnapshot]
        let stderr: String
        let exitCode: Int32
    }

    static func collect() throws -> Result {
        let task = Process()
        let stdout = Pipe()
        let stderr = Pipe()

        task.standardOutput = stdout
        task.standardError = stderr
        task.executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
        task.arguments = [
            "-nP",
            "-iTCP",
            "-sTCP:LISTEN",
            "-F",
            "pcufn"
        ]

        let result = try ProcessOutputCapture.execute(task: task, pipes: [stdout, stderr])
        let stdoutData = result.outputs[0]
        let stderrData = result.outputs[1]
        let stdoutString = String(data: stdoutData, encoding: .utf8) ?? ""
        let stderrString = String(data: stderrData, encoding: .utf8) ?? ""

        return Result(
            listeners: NetworkListenerParser.parse(stdoutString),
            stderr: stderrString,
            exitCode: result.status
        )
    }
}
