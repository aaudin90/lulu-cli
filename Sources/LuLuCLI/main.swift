import Foundation
import Darwin

// MARK: - Rule class (mirrors LuLu's Rule.m NSSecureCoding)

@objc(Rule)
class Rule: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }

    @objc var uuid: String?
    @objc var key: String?
    @objc var pid: NSNumber?
    @objc var path: String?
    @objc var name: String?
    @objc var csInfo: NSDictionary?
    @objc var endpointAddr: String?
    @objc var endpointHost: String?
    @objc var isEndpointAddrRegex: NSNumber = 0
    @objc var endpointPort: String?
    @objc var type: NSNumber?
    @objc var scope: NSNumber?
    @objc var action: NSNumber?
    @objc var isDisabled: NSNumber?
    @objc var creation: Date?
    @objc var expiration: Date?

    override init() { super.init() }

    required init?(coder decoder: NSCoder) {
        super.init()
        key = decoder.decodeObject(of: NSString.self, forKey: "key") as String?
        uuid = decoder.decodeObject(of: NSString.self, forKey: "uuid") as String?
        pid = decoder.decodeObject(of: NSNumber.self, forKey: "pid")
        path = decoder.decodeObject(of: NSString.self, forKey: "path") as String?
        name = decoder.decodeObject(of: NSString.self, forKey: "name") as String?
        csInfo = decoder.decodeObject(of: [NSDictionary.self, NSArray.self, NSString.self, NSNumber.self], forKey: "csInfo") as? NSDictionary
        if decoder.containsValue(forKey: "isEndpointAddrRegex") {
            isEndpointAddrRegex = decoder.decodeObject(of: NSNumber.self, forKey: "isEndpointAddrRegex") ?? 0
        }
        endpointAddr = decoder.decodeObject(of: NSString.self, forKey: "endpointAddr") as String?
        endpointHost = decoder.decodeObject(of: NSString.self, forKey: "endpointHost") as String?
        endpointPort = decoder.decodeObject(of: NSString.self, forKey: "endpointPort") as String?
        type = decoder.decodeObject(of: NSNumber.self, forKey: "type")
        scope = decoder.decodeObject(of: NSNumber.self, forKey: "scope")
        action = decoder.decodeObject(of: NSNumber.self, forKey: "action")
        isDisabled = decoder.decodeObject(of: NSNumber.self, forKey: "isDisabled")
        creation = decoder.decodeObject(of: NSDate.self, forKey: "creation") as Date?
        expiration = decoder.decodeObject(of: NSDate.self, forKey: "expiration") as Date?
    }

    func encode(with encoder: NSCoder) {
        encoder.encode(key, forKey: "key")
        encoder.encode(uuid, forKey: "uuid")
        encoder.encode(pid, forKey: "pid")
        encoder.encode(path, forKey: "path")
        encoder.encode(name, forKey: "name")
        encoder.encode(csInfo, forKey: "csInfo")
        encoder.encode(isEndpointAddrRegex, forKey: "isEndpointAddrRegex")
        encoder.encode(endpointAddr, forKey: "endpointAddr")
        encoder.encode(endpointHost, forKey: "endpointHost")
        encoder.encode(endpointPort, forKey: "endpointPort")
        encoder.encode(type, forKey: "type")
        encoder.encode(scope, forKey: "scope")
        encoder.encode(action, forKey: "action")
        encoder.encode(isDisabled, forKey: "isDisabled")
        encoder.encode(creation, forKey: "creation")
        encoder.encode(expiration, forKey: "expiration")
    }

    var actionString: String {
        switch action?.intValue {
        case 0: return "Block"
        case 1: return "Allow"
        default: return "Unknown(\(action?.intValue ?? -1))"
        }
    }

    var typeString: String {
        switch type?.intValue {
        case 0: return "default"
        case 1: return "apple"
        case 2: return "baseline"
        case 3: return "user"
        case 4: return "passive"
        case 5: return "recent"
        default: return "unknown(\(type?.intValue ?? -1))"
        }
    }
}

// MARK: - Constants

let RULES_FILE = "/Library/Objective-See/LuLu/rules.plist"
let KEY_RULES = "rules"
let KEY_CS_INFO = "signingInfo"

let RULE_STATE_BLOCK: NSNumber = 0
let RULE_STATE_ALLOW: NSNumber = 1
let RULE_TYPE_USER: NSNumber = 3
let ACTION_SCOPE_ENDPOINT: NSNumber = 1

// MARK: - Load/Save

private let knownRuleFields: Set<String> = [
    "$class", "uuid", "key", "pid", "path", "name", "csInfo", "endpointAddr",
    "endpointHost", "isEndpointAddrRegex", "endpointPort", "type", "scope",
    "action", "isDisabled", "creation", "expiration"
]

func inferredAddressType(_ address: String?) -> Int {
    guard let value = address, !value.isEmpty, value != "*" else { return 0 }
    if value.rangeOfCharacter(from: CharacterSet(charactersIn: "\\()[]{}|^$+?")) != nil { return 1 }
    if value.contains("*") { return 3 }
    func family(_ value: String) -> Int32? {
        var v4 = in_addr()
        if value.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return AF_INET }
        var v6 = in6_addr()
        if value.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 { return AF_INET6 }
        return nil
    }
    func trimmed(_ value: Substring) -> String { String(value).trimmingCharacters(in: .whitespaces) }
    if let slash = value.firstIndex(of: "/") {
        let host = trimmed(value[..<slash])
        let prefix = trimmed(value[value.index(after: slash)...])
        guard !prefix.isEmpty, prefix.unicodeScalars.allSatisfy({ CharacterSet.decimalDigits.contains($0) }),
              let ipFamily = family(host) else { return 0 }
        let bits = (prefix as NSString).integerValue
        return bits >= 0 && bits <= (ipFamily == AF_INET ? 32 : 128) ? 2 : 0
    }
    if let dash = value.firstIndex(of: "-") {
        let left = trimmed(value[..<dash])
        let right = trimmed(value[value.index(after: dash)...])
        guard let first = family(left), let second = family(right), first == second else { return 0 }
        return 2
    }
    return 0
}

struct ArchiveInspection {
    let data: Data
    let legacyValues: [String: Int]
    let unknownFields: Bool
}

func inspectArchive(_ data: Data) throws -> ArchiveInspection {
    // Convert Foundation's opaque UID objects into public CF$UID dictionaries in XML.
    guard data.count <= 64 * 1024 * 1024 else { throw ArchiveError.invalid }
    let original = try PropertyListSerialization.propertyList(from: data, options: [], format: nil)
    let xml = try PropertyListSerialization.data(fromPropertyList: original, format: .xml, options: 0)
    guard xml.count <= 256 * 1024 * 1024,
          let xmlText = String(data: xml, encoding: .utf8),
          !xmlText.contains("<key>PreflightUID</key>"),
          let preflightData = xmlText.replacingOccurrences(of: "<key>CF$UID</key>", with: "<key>PreflightUID</key>").data(using: .utf8),
          var archive = try PropertyListSerialization.propertyList(from: preflightData, options: [], format: nil) as? [String: Any],
          var objects = archive["$objects"] as? [Any], objects.count <= 1_000_000 else {
        throw ArchiveError.invalid
    }
    func dereference(_ value: Any?) -> Any? {
        guard let reference = value as? [String: Any], reference.count == 1,
              let uid = reference["PreflightUID"] as? NSNumber else { return nil }
        let index = uid.intValue
        return index >= 0 && index < objects.count ? objects[index] : nil
    }
    var legacy = [String: Int]()
    var seen = Set<String>()
    var unknown = false
    for index in objects.indices {
        guard var item = objects[index] as? [String: Any],
              let cls = dereference(item["$class"]) as? [String: Any],
              let className = cls["$classname"] as? String, className == "Rule" else { continue }
        unknown = unknown || !Set(item.keys).isSubset(of: knownRuleFields)
        guard let id = dereference(item["uuid"]) as? String, !id.isEmpty,
              seen.insert(id).inserted else { throw ArchiveError.invalid }
        let endpoint: String?
        if let encodedAddress = item["endpointAddr"], let decoded = dereference(encodedAddress) {
            if let ref = encodedAddress as? [String: Any],
               let uid = ref["PreflightUID"] as? NSNumber, uid.intValue == 0 { endpoint = nil }
            else if let value = decoded as? String { endpoint = value }
            else { throw ArchiveError.invalid }
        } else if item["endpointAddr"] == nil { endpoint = nil }
        else { throw ArchiveError.invalid }
        if let encoded = item["isEndpointAddrRegex"] {
            if encoded is [String: Any] {
                guard let value = dereference(encoded) as? NSNumber,
                      value.doubleValue == Double(value.intValue), (0...3).contains(value.intValue) else {
                    throw ArchiveError.invalid
                }
            } else {
                guard let value = encoded as? NSNumber, value.doubleValue == Double(value.intValue) else {
                    throw ArchiveError.invalid
                }
                legacy[id] = inferredAddressType(endpoint)
                item.removeValue(forKey: "isEndpointAddrRegex")
                objects[index] = item
            }
        } else {
            legacy[id] = inferredAddressType(endpoint)
        }
    }
    archive["$objects"] = objects
    let normalized = try PropertyListSerialization.data(fromPropertyList: archive, format: .xml, options: 0)
    guard let normalizedText = String(data: normalized, encoding: .utf8),
          let decodingData = normalizedText.replacingOccurrences(of: "<key>PreflightUID</key>", with: "<key>CF$UID</key>").data(using: .utf8) else { throw ArchiveError.invalid }
    return ArchiveInspection(data: decodingData, legacyValues: legacy, unknownFields: unknown)
}

enum ArchiveError: Error { case invalid }

func decodeRules(_ data: Data, mutating: Bool = false) -> NSMutableDictionary? {
    let classes: [AnyClass] = [NSDictionary.self, NSMutableDictionary.self, NSArray.self, NSMutableArray.self,
                               NSString.self, NSNumber.self, NSSet.self, NSMutableSet.self, NSDate.self, Rule.self]
    do {
        let inspection = try inspectArchive(data)
        if inspection.unknownFields {
            if mutating { fputs("Error: unsupported Rule fields; refusing to write\n", stderr); return nil }
            fputs("Warning: archive has unsupported Rule fields\n", stderr)
        }
        let unarchived = try NSKeyedUnarchiver.unarchivedObject(ofClasses: classes, from: inspection.data)
        guard let dict = unarchived as? NSDictionary, let mutable = dict.mutableCopy() as? NSMutableDictionary else {
            throw ArchiveError.invalid
        }
        guard mutable.allKeys as? [String] != nil else { throw ArchiveError.invalid }
        var restored = Set<String>()
        for entry in mutable.allValues {
            guard let entry = entry as? NSDictionary, let rules = entry[KEY_RULES] as? [Rule] else {
                throw ArchiveError.invalid
            }
            for rule in rules {
                guard let uuid = rule.uuid else { throw ArchiveError.invalid }
                if let value = inspection.legacyValues[uuid] {
                    rule.isEndpointAddrRegex = NSNumber(value: value)
                    restored.insert(uuid)
                }
                guard (0...3).contains(rule.isEndpointAddrRegex.intValue) else { throw ArchiveError.invalid }
            }
        }
        guard restored.count == inspection.legacyValues.count else { throw ArchiveError.invalid }
        return mutable
    } catch {
        fputs("Error: unsupported or malformed rules archive\n", stderr)
        return nil
    }
}

func loadRules(from path: String) -> NSMutableDictionary? {
    do { return decodeRules(try snapshot(path).0) }
    catch { fputs("Error: cannot read rules file safely\n", stderr); return nil }
}

enum MutationError: Error, CustomStringConvertible {
    case message(String)
    var description: String { if case let .message(text) = self { return text }; return "mutation failed" }
}

func isSystemRulesPath(_ path: String, root: String = "/Library/Objective-See/LuLu") -> Bool {
    let base = URL(fileURLWithPath: root).standardizedFileURL.resolvingSymlinksInPath().path
    let resolved = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
    return resolved == base || resolved.hasPrefix(base + "/")
}

func requireStoppedLuLu() throws {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/bin/ps")
    task.arguments = ["-axo", "pid=,comm="]
    let data: Data
    do { data = try captureLogProcess(task, timeout: 5, limit: 8 * 1024 * 1024) }
    catch { throw MutationError.message("cannot inspect LuLu processes") }
    guard let text = String(data: data, encoding: .utf8), !text.isEmpty else {
        throw MutationError.message("cannot inspect LuLu processes")
    }
    for line in text.split(separator: "\n") {
        let trimmed = line.trimmingCharacters(in: .whitespaces)
        guard let split = trimmed.firstIndex(where: { $0.isWhitespace }),
              Int(trimmed[..<split]) != nil else { throw MutationError.message("ambiguous process list") }
        let path = trimmed[split...].trimmingCharacters(in: .whitespaces)
        guard !path.isEmpty else { throw MutationError.message("ambiguous process list") }
        let basename = (path as NSString).lastPathComponent
        if basename == "LuLu" || basename == "com.objective-see.lulu.extension" {
            throw MutationError.message("LuLu must be stopped before a system archive write")
        }
    }
}

func checkMutationPermission(system: Bool, offline: Bool, uid: uid_t, checkStopped: () throws -> Void) throws {
    if system {
        guard uid == 0 else { throw MutationError.message("system archive writes require root") }
        guard offline else { throw MutationError.message("system archive writes require --offline") }
        try checkStopped()
    }
}

struct FileIdentity: Equatable {
    let dev: dev_t
    let inode: ino_t
    let size: off_t
    let seconds: Int
    let nanoseconds: Int
    let mode: mode_t
    let uid: uid_t
    let gid: gid_t
    let changeSeconds: Int
    let changeNanoseconds: Int
    init(_ value: stat) {
        dev = value.st_dev; inode = value.st_ino; size = value.st_size
        seconds = value.st_mtimespec.tv_sec; nanoseconds = value.st_mtimespec.tv_nsec
        mode = value.st_mode; uid = value.st_uid; gid = value.st_gid
        changeSeconds = value.st_ctimespec.tv_sec; changeNanoseconds = value.st_ctimespec.tv_nsec
    }
}

func snapshot(_ path: String) throws -> (Data, stat) {
    let fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else { throw MutationError.message("cannot open archive without following symlinks") }
    defer { close(fd) }
    var info = stat()
    let limit = 64 * 1024 * 1024
    guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, info.st_size >= 0,
          info.st_size <= limit else {
        throw MutationError.message("archive must be a regular file no larger than 64 MiB")
    }
    var data = Data()
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while data.count <= limit {
        let requested = min(buffer.count, limit + 1 - data.count)
        let count = read(fd, &buffer, requested)
        if count < 0 { throw MutationError.message("cannot read archive") }
        if count == 0 { break }
        data.append(contentsOf: buffer.prefix(count))
    }
    guard data.count <= limit else { throw MutationError.message("archive exceeds 64 MiB") }
    var after = stat()
    guard fstat(fd, &after) == 0, FileIdentity(info) == FileIdentity(after), Int64(data.count) == info.st_size else {
        throw MutationError.message("archive changed while reading")
    }
    return (data, info)
}

func requireUnchanged(_ path: String, data: Data, identity: FileIdentity) throws {
    let (current, info) = try snapshot(path)
    guard identity == FileIdentity(info), current == data else { throw MutationError.message("archive changed concurrently") }
}

func uniqueSibling(_ path: String, label: String) throws -> String {
    let url = URL(fileURLWithPath: path)
    let template = url.deletingLastPathComponent().appendingPathComponent(".\(url.lastPathComponent).\(label).XXXXXX").path
    var bytes = Array(template.utf8CString)
    let fd = mkstemp(&bytes)
    guard fd >= 0 else { throw MutationError.message("cannot create private sibling file") }
    close(fd)
    return String(cString: bytes)
}

func copyMetadataAndContents(_ source: String, _ target: String) throws {
    let sourceFD = open(source, O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard sourceFD >= 0 else { throw MutationError.message("cannot open source archive") }
    defer { close(sourceFD) }
    var sourceInfo = stat()
    guard fstat(sourceFD, &sourceInfo) == 0, (sourceInfo.st_mode & S_IFMT) == S_IFREG else {
        throw MutationError.message("source archive must be a regular file")
    }
    let targetFD = open(target, O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard targetFD >= 0 else { throw MutationError.message("cannot open sibling file") }
    defer { close(targetFD) }
    var targetInfo = stat()
    guard fstat(targetFD, &targetInfo) == 0, (targetInfo.st_mode & S_IFMT) == S_IFREG else {
        throw MutationError.message("sibling must be a regular file")
    }
    guard fcopyfile(sourceFD, targetFD, nil, UInt32(COPYFILE_ALL)) == 0, fsync(targetFD) == 0 else {
        throw MutationError.message("cannot copy archive and metadata")
    }
}

func replaceContents(_ path: String, data: Data) throws {
    let fd = open(path, O_WRONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)
    guard fd >= 0 else { throw MutationError.message("cannot open private output") }
    defer { close(fd) }
    var info = stat()
    guard fstat(fd, &info) == 0, (info.st_mode & S_IFMT) == S_IFREG, ftruncate(fd, 0) == 0 else {
        throw MutationError.message("private output must be a regular file")
    }
    let success = data.withUnsafeBytes { buffer -> Bool in
        var offset = 0
        while offset < buffer.count {
            let n = write(fd, buffer.baseAddress!.advanced(by: offset), buffer.count - offset)
            if n <= 0 { return false }
            offset += n
        }
        return fsync(fd) == 0
    }
    guard success else { throw MutationError.message("cannot write private output") }
}

func withMutation(path: String, offline: Bool, operation: (NSMutableDictionary) -> Bool) throws {
    let system = isSystemRulesPath(path)
    try checkMutationPermission(system: system, offline: offline, uid: geteuid(), checkStopped: requireStoppedLuLu)
    let directory = URL(fileURLWithPath: path).deletingLastPathComponent().standardizedFileURL.resolvingSymlinksInPath().path
    var directoryInfo = stat()
    guard stat(directory, &directoryInfo) == 0, (directoryInfo.st_mode & S_IFMT) == S_IFDIR,
          directoryInfo.st_uid == geteuid(), (directoryInfo.st_mode & 0o022) == 0 else {
        throw MutationError.message("archive directory must be owned and not writable by others")
    }
    let lockPath = path + ".lulu-cli.lock"
    let lock = open(lockPath, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, S_IRUSR | S_IWUSR)
    guard lock >= 0 else { throw MutationError.message("cannot open lock") }
    defer { close(lock) }
    var lockInfo = stat()
    guard fstat(lock, &lockInfo) == 0, (lockInfo.st_mode & S_IFMT) == S_IFREG,
          lockInfo.st_uid == geteuid(), lockInfo.st_nlink == 1, (lockInfo.st_mode & 0o777) == 0o600 else {
        throw MutationError.message("unsafe lock ownership or permissions")
    }
    guard flock(lock, LOCK_EX | LOCK_NB) == 0 else { throw MutationError.message("archive busy") }
    defer { flock(lock, LOCK_UN) }
    let (original, info) = try snapshot(path)
    guard system || info.st_uid == geteuid() else { throw MutationError.message("archive must be user-owned") }
    guard let rules = decodeRules(original, mutating: true) else { throw MutationError.message("archive validation failed") }
    guard operation(rules) else { throw MutationError.message("no change made") }
    let encoded: Data
    do { encoded = try NSKeyedArchiver.archivedData(withRootObject: rules, requiringSecureCoding: true) }
    catch { throw MutationError.message("archive encoding failed") }
    try requireUnchanged(path, data: original, identity: FileIdentity(info))
    let backup = try uniqueSibling(path, label: "backup")
    var keepBackup = false
    defer { if !keepBackup { unlink(backup) } }
    try copyMetadataAndContents(path, backup)
    guard let backupData = try? Data(contentsOf: URL(fileURLWithPath: backup)), backupData == original else {
        throw MutationError.message("backup verification failed")
    }
    let temp = try uniqueSibling(path, label: "tmp")
    defer { unlink(temp) }
    try copyMetadataAndContents(path, temp)
    try replaceContents(temp, data: encoded)
    var tempInfo = stat()
    guard lstat(temp, &tempInfo) == 0, (tempInfo.st_mode & 0o7777) == (info.st_mode & 0o7777),
          tempInfo.st_uid == info.st_uid, tempInfo.st_gid == info.st_gid else {
        throw MutationError.message("archive ownership or mode changed")
    }
    try requireUnchanged(path, data: original, identity: FileIdentity(info))
    try checkMutationPermission(system: system, offline: offline, uid: geteuid(), checkStopped: requireStoppedLuLu)
    guard rename(temp, path) == 0 else { throw MutationError.message("atomic replacement failed") }
    keepBackup = true
    print("Saved. Backup: \(backup)")
}

// MARK: - Commands

func listRules(_ rules: NSDictionary, filter: String? = nil) {
    guard let keys = rules.allKeys as? [String] else { fputs("Error: invalid archive keys\n", stderr); return }
    let sortedKeys = keys.sorted()

    for key in sortedKeys {
        guard let entry = rules[key] as? NSDictionary,
              let ruleArray = entry[KEY_RULES] as? [Rule] else { continue }

        if let f = filter, !key.localizedCaseInsensitiveContains(f) {
            // Check if any rule path matches
            let pathMatch = ruleArray.contains { $0.path?.localizedCaseInsensitiveContains(f) == true }
            if !pathMatch { continue }
        }

        print("[\(key)]")
        for rule in ruleArray {
            let disabled = rule.isDisabled?.boolValue == true ? " [DISABLED]" : ""
            let labels = ["EXACT", "REGEX", "CIDR", "GLOB"]
            let regex = " [\(labels[rule.isEndpointAddrRegex.intValue])]"
            print("  \(rule.uuid ?? "no-uuid") | \(rule.actionString) | addr=\(rule.endpointAddr ?? "*") port=\(rule.endpointPort ?? "*") | type=\(rule.typeString)\(disabled)\(regex)")
            if let p = rule.path, p != key {
                print("    path=\(p)")
            }
        }
    }
}

func addRule(_ rules: NSMutableDictionary, key: String, path: String, action: NSNumber, addr: String, port: String, isRegex: Bool = false) {
    let rule = Rule()
    rule.uuid = UUID().uuidString
    rule.key = key
    rule.path = path
    rule.name = (path as NSString).lastPathComponent
    rule.action = action
    rule.endpointAddr = addr
    rule.endpointPort = port
    rule.isEndpointAddrRegex = NSNumber(value: isRegex ? 1 : 0)
    rule.type = RULE_TYPE_USER
    rule.scope = ACTION_SCOPE_ENDPOINT
    rule.creation = Date()

    if let entry = rules[key] as? NSMutableDictionary,
       let ruleArray = entry[KEY_RULES] as? NSMutableArray {
        ruleArray.add(rule)
    } else if let entry = rules[key] as? NSDictionary {
        let mutableEntry = entry.mutableCopy() as! NSMutableDictionary
        if let existingRules = mutableEntry[KEY_RULES] as? NSArray {
            let mutableRules = existingRules.mutableCopy() as! NSMutableArray
            mutableRules.add(rule)
            mutableEntry[KEY_RULES] = mutableRules
        } else {
            mutableEntry[KEY_RULES] = NSMutableArray(object: rule)
        }
        rules[key] = mutableEntry
    } else {
        let entry = NSMutableDictionary()
        entry[KEY_RULES] = NSMutableArray(object: rule)
        rules[key] = entry
    }

}

func deleteRule(_ rules: NSMutableDictionary, key: String, uuid: String?) -> Bool {
    guard let entry = rules[key] as? NSDictionary else {
        fputs("Key not found: \(key)\n", stderr)
        return false
    }

    // If no UUID, delete entire key
    if uuid == nil {
        rules.removeObject(forKey: key)
        return true
    }

    let mutableEntry = entry.mutableCopy() as! NSMutableDictionary
    guard let ruleArray = mutableEntry[KEY_RULES] as? NSArray else { return false }
    let mutableRules = ruleArray.mutableCopy() as! NSMutableArray

    let idx = mutableRules.indexOfObject(passingTest: { obj, _, _ in
        (obj as? Rule)?.uuid == uuid
    })

    if idx == NSNotFound {
        fputs("UUID not found: \(uuid!)\n", stderr)
        return false
    }

    mutableRules.removeObject(at: idx)

    if mutableRules.count == 0 {
        rules.removeObject(forKey: key)
    } else {
        mutableEntry[KEY_RULES] = mutableRules
        rules[key] = mutableEntry
    }

    return true
}

func deleteRuleByMatch(_ rules: NSMutableDictionary, key: String, action: Int?, addr: String?, port: String?) -> Bool {
    guard let entry = rules[key] as? NSDictionary,
          let ruleArray = entry[KEY_RULES] as? NSArray else {
        fputs("Key not found: \(key)\n", stderr)
        return false
    }

    let mutableEntry = entry.mutableCopy() as! NSMutableDictionary
    let mutableRules = ruleArray.mutableCopy() as! NSMutableArray
    var deleted = 0

    for i in stride(from: mutableRules.count - 1, through: 0, by: -1) {
        guard let rule = mutableRules[i] as? Rule else { continue }
        var matches = true
        if let a = action, rule.action?.intValue != a { matches = false }
        if let ad = addr, rule.endpointAddr != ad { matches = false }
        if let p = port, rule.endpointPort != p { matches = false }
        if matches {
            mutableRules.removeObject(at: i)
            deleted += 1
        }
    }

    if deleted == 0 {
        fputs("No matching rules found\n", stderr)
        return false
    }

    if mutableRules.count == 0 {
        rules.removeObject(forKey: key)
    } else {
        mutableEntry[KEY_RULES] = mutableRules
        rules[key] = mutableEntry
    }

    return true
}

func recentBlocks(_ rules: NSDictionary, count: Int = 20) {
    var allBlocks: [(key: String, rule: Rule)] = []

    guard let keys = rules.allKeys as? [String] else { fputs("Error: invalid archive keys\n", stderr); return }
    for key in keys {
        guard let entry = rules[key] as? NSDictionary,
              let ruleArray = entry[KEY_RULES] as? [Rule] else { continue }
        for rule in ruleArray {
            if rule.action?.intValue == 0 { // BLOCK
                allBlocks.append((key: key, rule: rule))
            }
        }
    }

    // Sort by creation date, newest first
    allBlocks.sort { ($0.rule.creation ?? .distantPast) > ($1.rule.creation ?? .distantPast) }

    let df = DateFormatter()
    df.dateFormat = "yyyy-MM-dd HH:mm"

    let shown = allBlocks.prefix(count)
    for (key, rule) in shown {
        let date = rule.creation.map { df.string(from: $0) } ?? "unknown"
        let disabled = rule.isDisabled?.boolValue == true ? " [DISABLED]" : ""
        print("\(date) | \(rule.endpointAddr ?? "*"):\(rule.endpointPort ?? "*") | \(rule.typeString)\(disabled)")
        print("  key=\(key) uuid=\(rule.uuid ?? "?")")
        if let p = rule.path, p != key {
            print("  path=\(p)")
        }
    }
    print("\n\(allBlocks.count) total block rules, showing \(shown.count) most recent")
}

func toggleRule(_ rules: NSMutableDictionary, key: String, uuid: String, enable: Bool) -> Bool {
    guard let entry = rules[key] as? NSDictionary,
          let ruleArray = entry[KEY_RULES] as? NSArray else {
        fputs("Key not found: \(key)\n", stderr)
        return false
    }

    let mutableEntry = entry.mutableCopy() as! NSMutableDictionary
    let mutableRules = ruleArray.mutableCopy() as! NSMutableArray

    for i in 0..<mutableRules.count {
        guard let rule = mutableRules[i] as? Rule, rule.uuid == uuid else { continue }
        rule.isDisabled = enable ? nil : NSNumber(value: 1)
        mutableEntry[KEY_RULES] = mutableRules
        rules[key] = mutableEntry
        return true
    }

    fputs("UUID not found: \(uuid)\n", stderr)
    return false
}

// MARK: - Usage and strict argument parsing

func usage() {
    print("""
    Usage: lulu-cli [--file PATH] [--offline] <command> [options]
      list [filter]                 List rules
      recent [N]                    List N most recent block rules
      logs [--last 5m] [--process PATH] [--limit N] [--json]
      add --key KEY --path PATH --action allow|block [--addr ADDR] [--port PORT] [--regex]
      delete --key KEY [--uuid UUID] Delete one rule, or all rules for KEY without UUID
      delete-match --key KEY [--action allow|block] [--addr ADDR] [--port PORT]
      enable|disable --key KEY --uuid UUID
      reload                        Unsupported; restart LuLu using its app
    --file selects an archive; --offline is required for system archive writes.
    System writes also require root and LuLu to be stopped.
    Each successful write creates a sibling backup. delete-match requires a filter.
    """)
}

func fail(_ message: String) -> Never {
    fputs("Error: \(message)\n", stderr)
    exit(1)
}

func parseFlags(_ arguments: [String], values: Set<String>, switches: Set<String> = []) -> [String: String] {
    var result = [String: String]()
    var index = 0
    while index < arguments.count {
        let flag = arguments[index]
        guard result[flag] == nil else { fail("duplicate option \(flag)") }
        if switches.contains(flag) {
            result[flag] = "true"
            index += 1
        } else if values.contains(flag) {
            guard index + 1 < arguments.count, !arguments[index + 1].hasPrefix("--"),
                  !arguments[index + 1].isEmpty else { fail("missing value for \(flag)") }
            result[flag] = arguments[index + 1]
            index += 2
        } else { fail("unknown argument") }
    }
    return result
}

func validPort(_ value: String) -> Bool {
    if value == "*" { return true }
    guard !value.isEmpty, value.allSatisfy({ $0.isASCII && $0.isNumber }),
          let n = Int(value), (1...65535).contains(n), String(n) == value else { return false }
    return true
}

func rulesPathForProfile(_ profile: Any?, root: String = "/Library/Objective-See/LuLu") throws -> String {
    let base = URL(fileURLWithPath: root, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
    guard let profile = profile else { return base.appendingPathComponent("rules.plist").path }
    guard let raw = profile as? String else { throw ArchiveError.invalid }
    if raw.isEmpty { return base.appendingPathComponent("rules.plist").path }
    guard raw.hasPrefix("/") else { throw ArchiveError.invalid }
    let selected = URL(fileURLWithPath: raw, isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
    if selected.path == base.path { return base.appendingPathComponent("rules.plist").path }
    let profiles = base.appendingPathComponent("Profiles", isDirectory: true).standardizedFileURL.resolvingSymlinksInPath()
    guard profiles.deletingLastPathComponent().path == base.path,
          selected.deletingLastPathComponent().path == profiles.path,
          selected.lastPathComponent != ".", selected.lastPathComponent != ".." else { throw ArchiveError.invalid }
    let unresolvedRules = selected.appendingPathComponent("rules.plist").standardizedFileURL
    guard (try? FileManager.default.destinationOfSymbolicLink(atPath: unresolvedRules.path)) == nil else { throw ArchiveError.invalid }
    let rules = unresolvedRules.resolvingSymlinksInPath()
    guard rules.deletingLastPathComponent().path == selected.path else { throw ArchiveError.invalid }
    return rules.path
}

func defaultRulesPath() -> String {
    let preferences = "/Library/Objective-See/LuLu/preferences.plist"
    guard FileManager.default.fileExists(atPath: preferences) else { return RULES_FILE }
    guard let data = try? Data(contentsOf: URL(fileURLWithPath: preferences)),
          let prefs = (try? PropertyListSerialization.propertyList(from: data, format: nil)) as? [String: Any] else {
        fail("cannot read LuLu preferences")
    }
    guard let path = try? rulesPathForProfile(prefs["currentProfile"]) else { fail("invalid active profile") }
    return path
}

var commandArguments = Array(CommandLine.arguments.dropFirst())
var fileOverride: String?
var offline = false
while let first = commandArguments.first, first == "--file" || first == "--offline" {
    if first == "--file" {
        guard fileOverride == nil, commandArguments.count >= 2,
              !commandArguments[1].hasPrefix("--"), !commandArguments[1].isEmpty else {
            fail("--file requires one path")
        }
        fileOverride = commandArguments[1]
        commandArguments.removeFirst(2)
    } else {
        guard !offline else { fail("duplicate --offline") }
        offline = true
        commandArguments.removeFirst()
    }
}
guard let command = commandArguments.first else { usage(); exit(1) }
let arguments = Array(commandArguments.dropFirst())
if command == "logs" {
    exit(runLogsCommand(arguments))
}
if ["help", "--help", "-h"].contains(command) {
    guard arguments.isEmpty else { fail("unexpected arguments") }
    usage(); exit(0)
}

switch command {
case "list":
    guard arguments.count <= 1, arguments.first?.hasPrefix("-") != true else { fail("invalid list arguments") }
    let path = fileOverride ?? defaultRulesPath()
    guard let rules = loadRules(from: path) else { exit(1) }
    listRules(rules, filter: arguments.first)
case "recent":
    guard arguments.count <= 1 else { fail("invalid recent arguments") }
    var count = 20
    if let raw = arguments.first {
        guard !raw.isEmpty, raw.allSatisfy({ $0.isASCII && $0.isNumber }), let n = Int(raw), n >= 0 else {
            fail("invalid recent count")
        }
        count = n
    }
    let path = fileOverride ?? defaultRulesPath()
    guard let rules = loadRules(from: path) else { exit(1) }
    recentBlocks(rules, count: count)
case "add":
    let options = parseFlags(arguments, values: ["--key", "--path", "--action", "--addr", "--port"], switches: ["--regex"])
    guard let key = options["--key"], let app = options["--path"], let action = options["--action"],
          ["allow", "block"].contains(action) else { fail("required key, path and valid action") }
    let addr = options["--addr"] ?? "*", port = options["--port"] ?? "*"
    guard validPort(port) else { fail("invalid port") }
    if options["--regex"] != nil && (try? NSRegularExpression(pattern: addr)) == nil { fail("invalid regex") }
    let path = fileOverride ?? defaultRulesPath()
    do {
        try withMutation(path: path, offline: offline) { rules in
            addRule(rules, key: key, path: app, action: action == "allow" ? RULE_STATE_ALLOW : RULE_STATE_BLOCK,
                    addr: addr, port: port, isRegex: options["--regex"] != nil)
            return true
        }
    } catch { fail("\(error)") }
case "delete", "delete-match", "enable", "disable":
    let allowed: Set<String> = command == "delete" ? ["--key", "--uuid"] :
        command == "delete-match" ? ["--key", "--action", "--addr", "--port"] : ["--key", "--uuid"]
    let options = parseFlags(arguments, values: allowed)
    guard let key = options["--key"] else { fail("missing --key") }
    if command == "enable" || command == "disable" {
        guard options["--uuid"] != nil else { fail("missing --uuid") }
    }
    if let action = options["--action"], !["allow", "block"].contains(action) { fail("invalid action") }
    if let port = options["--port"], !validPort(port) { fail("invalid port") }
    if command == "delete-match" && options["--action"] == nil && options["--addr"] == nil && options["--port"] == nil {
        fail("delete-match requires at least one filter")
    }
    let path = fileOverride ?? defaultRulesPath()
    do {
        try withMutation(path: path, offline: offline) { rules in
            if command == "delete" { return deleteRule(rules, key: key, uuid: options["--uuid"]) }
            if command == "delete-match" {
                let action = options["--action"].map { $0 == "allow" ? 1 : 0 }
                return deleteRuleByMatch(rules, key: key, action: action, addr: options["--addr"], port: options["--port"])
            }
            return toggleRule(rules, key: key, uuid: options["--uuid"]!, enable: command == "enable")
        }
    } catch { fail("\(error)") }

case "reload":
    guard arguments.isEmpty, fileOverride == nil, !offline else { fail("invalid reload arguments") }
    fail("live reload is unsupported; restart LuLu using its app")

default:
    fputs("Unknown command\n", stderr)
    usage()
    exit(1)
}
