import Foundation
import Darwin

struct LogOptions {
    var last = "5m"
    var process: String?
    var limit = 200
    var json = false
}

enum LogsFailure: Error {
    case arguments, unavailable, failed, timeout, oversized, invalidJSON
}

func parseLogOptions(_ arguments: [String]) throws -> LogOptions {
    var result = LogOptions()
    var seen = Set<String>()
    var index = 0
    while index < arguments.count {
        let option = arguments[index]
        guard ["--last", "--process", "--limit", "--json"].contains(option),
              seen.insert(option).inserted else {
            throw LogsFailure.arguments
        }
        if option == "--json" {
            result.json = true
            index += 1
            continue
        }
        index += 1
        guard index < arguments.count else { throw LogsFailure.arguments }
        let value = arguments[index]
        switch option {
        case "--last":
            guard let unit = value.last,
                  let multiplier = ["s": 1, "m": 60, "h": 3600, "d": 86400][String(unit)],
                  !value.dropLast().isEmpty,
                  value.dropLast().allSatisfy({ $0.isASCII && $0.isNumber }),
                  let duration = Int(value.dropLast()), duration > 0,
                  duration <= 604800 / multiplier else {
                throw LogsFailure.arguments
            }
            result.last = value
        case "--limit":
            guard !value.isEmpty, value.allSatisfy({ $0.isASCII && $0.isNumber }),
                  let limit = Int(value), (1...10000).contains(limit) else {
                throw LogsFailure.arguments
            }
            result.limit = limit
        case "--process":
            guard let path = safeLogPath(value) else { throw LogsFailure.arguments }
            result.process = path
        default:
            throw LogsFailure.arguments
        }
        index += 1
    }
    return result
}

func safeLogPath(_ path: String) -> String? {
    guard path.hasPrefix("/"), !path.contains("<private>"),
          !path.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
        return nil
    }
    return (path as NSString).standardizingPath
}

struct LogEvent: Encodable {
    let timestamp: String
    let action = "block"
    let process_path: String?
    let remote_address: String?
    let remote_port: Int?
    let app_pid: Int? = nil
    let `protocol`: String? = nil

    enum CodingKeys: String, CodingKey {
        case timestamp, action, process_path, remote_address, remote_port, app_pid, `protocol`
    }
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(timestamp, forKey: .timestamp)
        try c.encode(action, forKey: .action)
        try c.encode(process_path, forKey: .process_path)
        try c.encode(remote_address, forKey: .remote_address)
        try c.encode(remote_port, forKey: .remote_port)
        try c.encodeNil(forKey: .app_pid)
        try c.encodeNil(forKey: .protocol)
    }
}

func parseLogEndpoint(_ text: String) -> (String, Int)? {
    var host: String
    let portText: String
    if text.hasPrefix("[") {
        guard let end = text.firstIndex(of: "]"), text.index(after: end) < text.endIndex,
              text[text.index(after: end)] == ":" else {
            return nil
        }
        host = String(text[text.index(after: text.startIndex)..<end])
        portText = String(text[text.index(end, offsetBy: 2)...])
        var address = in6_addr()
        guard host.withCString({ inet_pton(AF_INET6, $0, &address) }) == 1 else { return nil }
    } else {
        guard let colon = text.lastIndex(of: ":") else { return nil }
        host = String(text[..<colon])
        portText = String(text[text.index(after: colon)...])
        guard !host.isEmpty, host.count <= 253, !host.contains(":"), host.unicodeScalars.allSatisfy({ $0.isASCII }),
              host.split(separator: ".", omittingEmptySubsequences: false).allSatisfy({ part in
                  !part.isEmpty && part.count <= 63 && part.first != "-" && part.last != "-"
                      && part.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-") }
              }) else {
            return nil
        }
        if host.allSatisfy({ $0.isNumber || $0 == "." }) {
            var address = in_addr()
            guard host.withCString({ inet_pton(AF_INET, $0, &address) }) == 1 else { return nil }
        }
    }
    guard !portText.isEmpty, portText.allSatisfy({ $0.isASCII && $0.isNumber }),
          let port = Int(portText), (1...65535).contains(port) else {
        return nil
    }
    return (host, port)
}

struct LogsOutput: Encodable {
    let schema_version = 1
    let status = "ok"
    let source = "macos_unified_log"
    let events: [LogEvent]
    let warnings: [String]
    let truncated: Bool
}

func parseLogData(_ data: Data, options: LogOptions) throws -> LogsOutput {
    let object: Any
    do {
        object = try JSONSerialization.jsonObject(with: data)
    } catch {
        throw LogsFailure.invalidJSON
    }
    guard let records = object as? [Any] else { throw LogsFailure.invalidJSON }
    var events: [(Int, Date, LogEvent)] = []
    var malformed = 0
    var unknownEndpoint = 0
    var hiddenPath = 0
    let timestampPattern = try! NSRegularExpression(pattern: "^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9:.+-]+(?:Z)?$")
    let fractionalDate = ISO8601DateFormatter()
    fractionalDate.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    let plainDate = ISO8601DateFormatter()
    for (index, item) in records.enumerated() {
        guard let record = item as? [String: Any], let message = record["eventMessage"] as? String,
              message.hasPrefix("blocked "), let timestamp = record["timestamp"] as? String,
              timestampPattern.firstMatch(in: timestamp, range: NSRange(timestamp.startIndex..., in: timestamp)) != nil,
              let date = fractionalDate.date(from: timestamp.replacingOccurrences(of: " ", with: "T"))
                ?? plainDate.date(from: timestamp.replacingOccurrences(of: " ", with: "T")),
              let arrow = message.range(of: " -> "),
              let rule = message.range(of: " (rule: ", options: .backwards),
              arrow.upperBound <= rule.lowerBound else {
            malformed += 1
            continue
        }
        let pathStart = message.index(message.startIndex, offsetBy: 8)
        guard arrow.lowerBound >= pathStart else {
            malformed += 1
            continue
        }
        let pathText = String(message[pathStart..<arrow.lowerBound])
        guard !pathText.trimmingCharacters(in: .whitespaces).isEmpty else {
            malformed += 1
            continue
        }
        let path = safeLogPath(pathText)
        if path == nil { hiddenPath += 1 }
        if let wanted = options.process, path != wanted { continue }
        let endpoint = parseLogEndpoint(String(message[arrow.upperBound..<rule.lowerBound]))
        if endpoint == nil { unknownEndpoint += 1 }
        let event = LogEvent(timestamp: timestamp, process_path: path, remote_address: endpoint?.0, remote_port: endpoint?.1)
        events.append((index, date, event))
    }
    events.sort { $0.1 == $1.1 ? $0.0 < $1.0 : $0.1 < $1.1 }
    let truncated = events.count > options.limit
    let selected = events.suffix(options.limit).map { $0.2 }
    var warnings = ["Unified log results are incomplete and do not prove that no blocks occurred."]
    if malformed > 0 { warnings.append("Ignored malformed records: \(malformed).") }
    if unknownEndpoint > 0 { warnings.append("Events with unavailable endpoints: \(unknownEndpoint).") }
    if hiddenPath > 0 { warnings.append("Events with unavailable process paths: \(hiddenPath).") }
    return LogsOutput(events: selected, warnings: warnings, truncated: truncated)
}

func fetchUnifiedLogs(last: String) throws -> Data {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
    process.arguments = [
        "show", "--last", last, "--style", "json", "--predicate",
        "subsystem == \"com.objective-see.lulu\" AND eventMessage BEGINSWITH \"blocked \"",
    ]
    return try captureLogProcess(process, timeout: 30, limit: 32 * 1024 * 1024)
}

func captureLogProcess(_ process: Process, timeout seconds: TimeInterval, limit: Int) throws -> Data {
    let stdout = Pipe()
    let stderr = Pipe()
    process.standardOutput = stdout
    process.standardError = stderr
    do {
        try process.run()
    } catch {
        throw LogsFailure.unavailable
    }
    let handles = [stdout.fileHandleForReading, stderr.fileHandleForReading]
    defer {
        for handle in handles {
            handle.closeFile()
        }
    }
    var descriptors = handles.map { handle in
        pollfd(fd: handle.fileDescriptor, events: Int16(POLLIN), revents: 0)
    }
    var readFailed = false
    for descriptor in descriptors {
        let flags = fcntl(descriptor.fd, F_GETFL)
        if flags < 0 || fcntl(descriptor.fd, F_SETFL, flags | O_NONBLOCK) < 0 {
            readFailed = true
        }
    }
    var output = Data()
    var exceeded = false
    let start = ProcessInfo.processInfo.systemUptime
    let deadline = start + seconds
    var buffer = [UInt8](repeating: 0, count: 65536)
    while !readFailed && !exceeded && (process.isRunning || descriptors.contains(where: { $0.fd >= 0 })) {
        let remaining = deadline - ProcessInfo.processInfo.systemUptime
        if remaining <= 0 { break }
        let waitMilliseconds = Int32(min(50, max(1, Int(remaining * 1000))))
        let result = poll(&descriptors, nfds_t(descriptors.count), waitMilliseconds)
        if result < 0 {
            if errno == EINTR { continue }
            readFailed = true
            break
        }
        for index in descriptors.indices where descriptors[index].fd >= 0 && descriptors[index].revents != 0 {
            while true {
                if ProcessInfo.processInfo.systemUptime >= deadline { break }
                let count = buffer.withUnsafeMutableBytes { bytes in
                    Darwin.read(descriptors[index].fd, bytes.baseAddress, bytes.count)
                }
                if count > 0 {
                    if index == 0 {
                        if count > limit - output.count {
                            exceeded = true
                            break
                        }
                        output.append(contentsOf: buffer.prefix(count))
                    }
                } else if count == 0 {
                    descriptors[index].fd = -1
                    break
                } else if errno == EINTR {
                    continue
                } else if errno == EAGAIN || errno == EWOULDBLOCK {
                    break
                } else {
                    readFailed = true
                    break
                }
            }
        }
    }
    let timedOut = !exceeded && !readFailed && (process.isRunning || descriptors.contains(where: { $0.fd >= 0 }))
    if process.isRunning {
        process.terminate()
        let grace = ProcessInfo.processInfo.systemUptime + 1
        while process.isRunning && ProcessInfo.processInfo.systemUptime < grace {
            Thread.sleep(forTimeInterval: 0.02)
        }
        if process.isRunning {
            _ = kill(process.processIdentifier, SIGKILL)
        }
    }
    process.waitUntilExit()
    if exceeded { throw LogsFailure.oversized }
    if timedOut { throw LogsFailure.timeout }
    if readFailed { throw LogsFailure.failed }
    guard process.terminationStatus == 0 else { throw LogsFailure.failed }
    return output
}

func runLogsCommand(_ arguments: [String]) -> Int32 {
    do {
        let options = try parseLogOptions(arguments)
        let result = try parseLogData(fetchUnifiedLogs(last: options.last), options: options)
        if options.json {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.sortedKeys]
            let data = try encoder.encode(result)
            print(String(decoding: data, as: UTF8.self))
        } else {
            for event in result.events {
                let path = event.process_path ?? "<unavailable>"
                let address = event.remote_address ?? "<unavailable>"
                let port = event.remote_port.map(String.init) ?? "?"
                print("\(event.timestamp) | block | \(path) | \(address):\(port)")
            }
            for warning in result.warnings {
                fputs("Warning: \(warning)\n", stderr)
            }
            if result.truncated {
                fputs("Warning: results truncated by --limit.\n", stderr)
            }
        }
        return 0
    } catch LogsFailure.arguments {
        fputs("Invalid logs arguments.\n", stderr)
        return 2
    } catch LogsFailure.timeout {
        fputs("Log query timed out.\n", stderr)
        return 1
    } catch LogsFailure.oversized {
        fputs("Log output exceeded 32 MiB; use a shorter --last.\n", stderr)
        return 1
    } catch LogsFailure.invalidJSON {
        fputs("Log query returned invalid JSON.\n", stderr)
        return 1
    } catch {
        fputs("Unified log query unavailable or failed.\n", stderr)
        return 1
    }
}
