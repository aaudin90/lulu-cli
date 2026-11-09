import Foundation

@objc(Rule)
final class FixtureRule: NSObject, NSSecureCoding {
    static var supportsSecureCoding: Bool { true }
    let index: Int
    let legacy: Bool
    let extra: Bool
    init(index: Int, legacy: Bool, extra: Bool) { self.index = index; self.legacy = legacy; self.extra = extra }
    required init?(coder: NSCoder) { fatalError("encode only") }
    func encode(with coder: NSCoder) {
        coder.encode("fixture-\(index)" as NSString, forKey: "uuid")
        coder.encode("fixture" as NSString, forKey: "key")
        coder.encode("/fixture/app" as NSString, forKey: "path")
        coder.encode(NSNumber(value: 123), forKey: "pid")
        coder.encode(["authority": "example"] as NSDictionary, forKey: "csInfo")
        coder.encode(NSNumber(value: 1), forKey: "action")
        coder.encode(NSNumber(value: 1), forKey: "isDisabled")
        coder.encode(Date(timeIntervalSince1970: 123456) as NSDate, forKey: "creation")
        coder.encode("example.com" as NSString, forKey: "endpointAddr")
        coder.encode("443" as NSString, forKey: "endpointPort")
        if legacy {
            if index < 2 { coder.encode(index == 1, forKey: "isEndpointAddrRegex") }
            else { coder.encode(index, forKey: "isEndpointAddrRegex") }
        } else {
            coder.encode(NSNumber(value: index), forKey: "isEndpointAddrRegex")
        }
        if extra { coder.encode("future" as NSString, forKey: "futureField") }
    }
}
let args = CommandLine.arguments
let legacy = args[2] == "legacy"
let extra = args[2] == "unknown"
let values = (0...3).map { FixtureRule(index: $0, legacy: legacy, extra: extra) }
let archive: NSDictionary = ["fixture": ["rules": values, "paths": Set(["/fixture/app"]), "metadata": "keep"]]
let data = try NSKeyedArchiver.archivedData(withRootObject: archive, requiringSecureCoding: true)
try data.write(to: URL(fileURLWithPath: args[1]))
