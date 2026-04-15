import XCTest
import ArgumentParser
@testable import sen

final class CLITests: XCTestCase {
    
    func testSentinelCLIConfiguration() {
        let config = SentinelCLI.configuration
        XCTAssertEqual(config.commandName, "sen")
        XCTAssertTrue(config.subcommands.contains(where: { $0 == RunCommand.self }))
        XCTAssertTrue(config.subcommands.contains(where: { $0 == StatusCommand.self }))
    }
    
    func testRunCommandParsing() throws {
        // When parsing a subcommand directly, omit the command name
        let command = try RunCommand.parse(["--daemon"])
        XCTAssertTrue(command.daemon)
        
        let command2 = try RunCommand.parse([])
        XCTAssertFalse(command2.daemon)
    }
    
    func testLogsCommandParsing() throws {
        let command = try LogsCommand.parse(["--raw"])
        XCTAssertTrue(command.raw)
    }
}
