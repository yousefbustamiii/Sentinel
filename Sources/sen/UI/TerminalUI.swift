import Foundation
import Darwin

/// Centralized UI component for consistent terminal output and interaction.
internal struct TerminalUI {
    
    enum Style {
        case standard
        case bold
        case boldMuted
        case success
        case error
        case warning
        case muted
    }
    
    // MARK: - Internals
    
    struct StyleRenderer {
        let isDarkMode: Bool
        let reset = "\u{001B}[0m"
        let bold = "\u{001B}[1m"
        
        static let current = StyleRenderer(
            isDarkMode: UserDefaults.standard.string(forKey: "AppleInterfaceStyle") == "Dark"
        )
        
        var tamperedIndicator: String {
            "\u{001B}[41;37m [!] TAMPERED \(reset)"
        }
        
        func color(for style: Style) -> String {
            switch style {
            case .standard:  return isDarkMode ? "\u{001B}[37m" : "\u{001B}[30m"
            case .bold:      return bold + (isDarkMode ? "\u{001B}[37m" : "\u{001B}[30m")
            case .boldMuted: return bold + (isDarkMode ? "\u{001B}[90m" : "\u{001B}[37m")
            case .success:   return bold + "\u{001B}[32m"
            case .error:     return bold + "\u{001B}[31m"
            case .warning:   return bold + "\u{001B}[33m"
            case .muted:     return isDarkMode ? "\u{001B}[90m" : "\u{001B}[37m"
            }
        }
    }
    
    static let renderer = StyleRenderer.current
    
    static var tamperedIndicator: String {
        renderer.tamperedIndicator
    }
}

// MARK: - Output Helpers

internal extension TerminalUI {
    
    static func printBanner() {
        let color = renderer.color(for: .standard)
        let reset = renderer.reset
        let banner = """
        \(color) ██████╗ ███████╗ ███╗   ██╗ ████████╗ ██╗ ███╗   ██╗ ███████╗ ██╗
        \(color) ██╔════╝ ██╔════╝ ████╗  ██║ ╚══██╔══╝ ██║ ████╗  ██║ ██╔════╝ ██║
        \(color) ╚█████╗  █████╗   ██╔██╗ ██║    ██║    ██║ ██╔██╗ ██║ █████╗   ██║
        \(color)  ╚═══██╗ ██╔══╝   ██║╚██╗██║    ██║    ██║ ██║╚██╗██║ ██╔══╝   ██║
        \(color) ██████╔╝ ███████╗ ██║ ╚████║    ██║    ██║ ██║ ╚████║ ███████╗ ███████╗
        \(color) ╚═════╝  ╚══════╝ ╚═╝  ╚═══╝    ╚═╝    ╚═╝ ╚═╝  ╚═══╝ ╚══════╝ ╚══════╝\(reset)
        """
        print(banner)
    }

    static func printSingle(_ text: String, style: Style = .standard) {
        let color = renderer.color(for: style)
        print("\(color)\(text)\(renderer.reset)")
    }
    
    static func space() {
        print("")
    }
    
    static func printSeparator() {
        print("\(renderer.color(for: .muted))----------------------------------------\(renderer.reset)")
    }
    
    static func printMenu(options: [String]) {
        let color = renderer.color(for: .standard)
        for (idx, option) in options.enumerated() {
            print("\(color)\(idx + 1). \(option)\(renderer.reset)")
            print("")
        }
    }
    
    /// Standardized action confirmation footer for CLI commands.
    static func printActionComplete(_ message: String) {
        printSingle(message, style: .success)
    }
}

// MARK: - Input Helpers

internal extension TerminalUI {
    
    static func readInput(prompt: String) -> String? {
        let color = renderer.color(for: .muted)
        print("\(color)\(prompt)\(renderer.reset)")
        print("")
        print("\(color)> \(renderer.reset)", terminator: "")
        return readLine()?.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    
    static func readPassword(message: String) -> String? {
        let muted = renderer.color(for: .muted)
        print("\(muted)\(renderer.bold)\(message)\(renderer.reset)")
        
        let prompt = "\(muted)Password: \(renderer.reset)"
        if let passPtr = getpass(prompt) {
            let pass = String(cString: passPtr)
            return pass.isEmpty ? nil : pass
        }
        return nil
    }
}

// MARK: - Forensic Rendering

internal extension TerminalUI {
    
    static func printLogEntries(_ logs: [LogEntry]) {
        let color = renderer.color(for: .standard)
        let reset = renderer.reset
        for (i, log) in logs.enumerated() {
            print("\(color)\(LogEntryFormatter.format(log))\(reset)")
            if i < logs.count - 1 { space() }
        }
    }

    static func printLogEntriesJSON(_ logs: [LogEntry]) {
        guard let data = try? StorageUtils.encoder.encode(logs),
              let str = String(data: data, encoding: .utf8) else { return }
        
        let color = renderer.color(for: .standard)
        print("\(color)\(str)\(renderer.reset)")
    }
}
