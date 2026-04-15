import Foundation

internal enum ProcessOutputCapture {
    static func execute(task: Process, pipes: [Pipe]) throws -> (status: Int32, outputs: [Data]) {
        let group = DispatchGroup()
        let lock = NSLock()
        var outputs = Array(repeating: Data(), count: pipes.count)

        for (index, pipe) in pipes.enumerated() {
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { group.leave() }
                let data = pipe.fileHandleForReading.readDataToEndOfFile()
                lock.lock()
                outputs[index] = data
                lock.unlock()
            }
        }

        try task.run()
        task.waitUntilExit()
        group.wait()

        return (task.terminationStatus, outputs)
    }
}
