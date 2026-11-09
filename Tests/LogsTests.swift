import Foundation

@main
struct LogsTests {
    static func main() throws {
        for args in [["--last"], ["--last", "0s"], ["--last", "8d"], ["--last", "-1m"], ["--limit", "10001"], ["--limit", "0"], ["--json", "--json"], ["--bad"], ["--process", "relative"], ["--last", "1m", "--last", "2m"]] {
            do { _ = try parseLogOptions(args); fatalError("accepted invalid arguments") } catch LogsFailure.arguments { }
        }
        let defaults = try parseLogOptions([])
        let maximum = try parseLogOptions(["--last", "7d", "--limit", "10000"])
        assert(defaults.last == "5m")
        assert(maximum.limit == 10000)
        let messages: [[String: Any]] = [
            ["timestamp": "2026-11-09 12:00:02.000000+0300", "eventMessage": "blocked /Applications/My App.app/Contents/MacOS/App -> [2001:db8::1]:443 (rule: SECRET_RULE_SENTINEL)"],
            ["timestamp": "2026-11-09 12:00:01.000000+0300", "eventMessage": "blocked /Applications/My App.app/Contents/MacOS/App -> 192.0.2.4:80 (rule: token=SECRET_SENTINEL)"],
            ["timestamp": "2026-11-09 12:00:03.000000+0300", "eventMessage": "blocked <private> -> <private> (rule: SECRET_SENTINEL)"],
            ["timestamp": "2026-11-09 12:00:04.000000+0300", "eventMessage": "blocked /tmp/x -> invalid:BAD (rule: SECRET_SENTINEL)"],
            ["timestamp": "2026-11-09 12:00:05.000000+0300", "eventMessage": "blocked malformed SECRET_SENTINEL"],
            ["timestamp": "SECRET_SENTINEL", "eventMessage": "blocked /tmp/x -> example.com:443 (rule: SECRET_SENTINEL)"],
        ]
        let data = try JSONSerialization.data(withJSONObject: messages)
        let result = try parseLogData(data, options: LogOptions())
        assert(result.events.count == 4)
        assert(result.events[0].remote_address == "192.0.2.4")
        assert(result.events[1].remote_address == "2001:db8::1")
        assert(result.events[2].process_path == nil && result.events[2].remote_address == nil)
        assert(result.events[3].remote_port == nil)
        assert(result.events.allSatisfy { $0.app_pid == nil && $0.protocol == nil })
        let encoded = String(decoding: try JSONEncoder().encode(result), as: UTF8.self)
        assert(!encoded.contains("SECRET_SENTINEL") && !encoded.contains("SECRET_RULE_SENTINEL"))
        assert(encoded.contains("\"app_pid\":null") && encoded.contains("\"protocol\":null"))
        let filtered = try parseLogData(data, options: parseLogOptions(["--process", "/Applications/My App.app/Contents/MacOS/../MacOS/App", "--limit", "1"]))
        assert(filtered.events.count == 1 && filtered.truncated && filtered.events[0].remote_address == "2001:db8::1")
        let empty = try parseLogData(Data("[]".utf8), options: LogOptions())
        assert(empty.events.isEmpty && !empty.warnings.isEmpty)
        let emptyPaths = ["blocked -> host:443 (rule: x)", "blocked  -> host:443 (rule: x)", "blocked    -> host:443 (rule: x)"].map {
            ["timestamp": "2026-11-09 12:00:00.000000+0300", "eventMessage": $0]
        }
        let emptyPathResult = try parseLogData(JSONSerialization.data(withJSONObject: emptyPaths), options: LogOptions())
        assert(emptyPathResult.events.isEmpty)
        assert(emptyPathResult.warnings.contains { $0.contains("malformed records: 3") })
        let offsets = [
            ["timestamp": "2026-11-09 12:00:00.000000+0300", "eventMessage": "blocked /tmp/earlier -> example.com:80 (rule: x)"],
            ["timestamp": "2026-11-09 11:00:00.000000+0000", "eventMessage": "blocked /tmp/later -> example.com:80 (rule: x)"],
            ["timestamp": "2026-99-99 11:00:00.000000+0000", "eventMessage": "blocked /tmp/bad -> example.com:80 (rule: x)"],
        ]
        let ordered = try parseLogData(JSONSerialization.data(withJSONObject: offsets), options: parseLogOptions(["--limit", "1"]))
        assert(ordered.events.count == 1 && ordered.events[0].process_path == "/tmp/later" && ordered.truncated)
        assert(ordered.warnings.contains { $0.contains("malformed records: 1") })
        for value in ["{}", "not-json"] {
            do { _ = try parseLogData(Data(value.utf8), options: LogOptions()); fatalError("accepted invalid JSON") } catch LogsFailure.invalidJSON { }
        }
        assert(parseLogEndpoint("host.example:443")?.0 == "host.example")
        for value in ["999.1.1.1:1", "[2001:broken]:80", "example.com:65536", "host/path:80", "host:0", "<private>"] { assert(parseLogEndpoint(value) == nil) }
        let python = "/usr/bin/python3"
        func child(_ code: String) -> Process {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: python)
            p.arguments = ["-c", code]
            return p
        }
        let success = try captureLogProcess(child("import sys; sys.stderr.write('SECRET_SENTINEL'); print('[]')"), timeout: 3, limit: 1024)
        assert(String(decoding: success, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == "[]")
        do { _ = try captureLogProcess(child("import time; time.sleep(3)"), timeout: 0.2, limit: 1024); fatalError("timeout missed") } catch LogsFailure.timeout { }
        let start = ProcessInfo.processInfo.systemUptime
        do {
            _ = try captureLogProcess(
                child("import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.8)'])"),
                timeout: 0.2, limit: 1024
            )
            fatalError("inherited pipe timeout missed")
        } catch LogsFailure.timeout { }
        assert(ProcessInfo.processInfo.systemUptime - start < 0.7)
        do { _ = try captureLogProcess(child("import sys; sys.stdout.write('x' * 100000); sys.stdout.flush()"), timeout: 3, limit: 1024); fatalError("overflow missed") } catch LogsFailure.oversized { }
        do { _ = try captureLogProcess(child("import sys; sys.stderr.write('x' * 200000); sys.exit(3)"), timeout: 3, limit: 1024); fatalError("failure missed") } catch LogsFailure.failed { }
        assert(runLogsCommand(["--last"]) == 2)
        print("LogsTests passed")
    }
}
