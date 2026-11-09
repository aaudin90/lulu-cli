import fcntl
import hashlib
import os
from pathlib import Path
import plistlib
import subprocess
import stat
import tempfile
import unittest

ROOT = Path(__file__).resolve().parent.parent
CLI = Path(os.environ.get("LULU_CLI_BIN", ROOT / ".build/release/lulu-cli"))


def run(*args):
    return subprocess.run([str(CLI), *map(str, args)], capture_output=True, text=True, timeout=20)


def digest(path):
    return hashlib.sha256(path.read_bytes()).digest()


def deref(objects, value):
    return objects[value.data] if isinstance(value, plistlib.UID) else value


def rules(path):
    objects = plistlib.loads(path.read_bytes())["$objects"]
    out = {}
    for obj in objects:
        if not isinstance(obj, dict) or "$class" not in obj:
            continue
        cls = deref(objects, obj["$class"])
        if isinstance(cls, dict) and cls.get("$classname") == "Rule":
            out[deref(objects, obj.get("uuid"))] = {k: deref(objects, v) for k, v in obj.items() if k != "$class"}
    return out


class CLIRegression(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="lulu-test-")
        cls.tmp_path = Path(cls.tmp.name)
        cls.generator = cls.tmp_path / "fixture-generator"
        subprocess.run(["swiftc", str(ROOT / "Tests/ArchiveFixtures.swift"), "-o", str(cls.generator)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def fixture(self, kind):
        path = self.tmp_path / (self._testMethodName + ".plist")
        subprocess.run([str(self.generator), str(path), kind], check=True, capture_output=True)
        return path

    def test_formats_read_and_roundtrip(self):
        for kind in ("modern", "legacy"):
            with self.subTest(kind=kind):
                path = self.fixture(kind)
                listing = run("--file", path, "list")
                self.assertEqual(listing.returncode, 0, listing.stderr)
                if kind == "modern":
                    for tag in ("EXACT", "REGEX", "CIDR", "GLOB"):
                        self.assertIn("[" + tag + "]", listing.stdout)
                else:
                    self.assertEqual(listing.stdout.count("[EXACT]"), 4)
                result = run("--file", path, "disable", "--key", "fixture", "--uuid", "fixture-0")
                self.assertEqual(result.returncode, 0, result.stderr)
                fields = rules(path)
                self.assertEqual([fields["fixture-" + str(i)]["isEndpointAddrRegex"] for i in range(4)], list(range(4)) if kind == "modern" else [0, 0, 0, 0])
                for i in range(4):
                    item = fields["fixture-" + str(i)]
                    self.assertEqual(item["pid"], 123)
                    self.assertEqual(item["endpointAddr"], "example.com")
                    self.assertEqual(item["endpointPort"], "443")
                    self.assertEqual(item["isDisabled"], 1)
                    self.assertIsNotNone(item["creation"])
                    self.assertIsNotNone(item["csInfo"])
                raw = plistlib.loads(path.read_bytes())
                self.assertIn("metadata", str(raw))
                self.assertIn("paths", str(raw))

    def test_legacy_address_inference_matches_vendor(self):
        cases = [(False, "*.example.com", 3), (True, "example.com", 0),
                 (3, "192.0.2.0/24", 2), (None, "^x$", 1),
                 (0, "192.0.2.1/33", 0), (0, "192.0.2.9-192.0.2.1", 2),
                 (0, "192.0.2.1-2001:db8::1", 0), (7, "*.example.com", 3)]
        for primitive, address, expected in cases:
            with self.subTest(primitive=primitive, address=address):
                path = self.fixture("legacy")
                archive = plistlib.loads(path.read_bytes())
                objects = archive["$objects"]
                obj = next(x for x in objects if isinstance(x, dict) and "isEndpointAddrRegex" in x)
                objects.append(address)
                obj["endpointAddr"] = plistlib.UID(len(objects) - 1)
                if primitive is None:
                    del obj["isEndpointAddrRegex"]
                else:
                    obj["isEndpointAddrRegex"] = primitive
                path.write_bytes(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY, sort_keys=False))
                result = run("--file", path, "disable", "--key", "fixture", "--uuid", "fixture-0")
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(rules(path)["fixture-0"]["isEndpointAddrRegex"], expected)

    def test_unknown_fields_refuse_write(self):
        path = self.fixture("unknown")
        before = digest(path)
        read = run("--file", path, "list")
        self.assertEqual(read.returncode, 0, read.stderr)
        self.assertIn("unsupported Rule fields", read.stderr)
        write = run("--file", path, "disable", "--key", "fixture", "--uuid", "fixture-0")
        self.assertNotEqual(write.returncode, 0)
        self.assertEqual(digest(path), before)

    def test_invalid_cli_never_changes_archive(self):
        path = self.fixture("modern")
        before = digest(path)
        cases = [["add", "--key"], ["add", "--key", "fixture", "--path", "/a", "--action", "typo"],
                 ["add", "--key", "fixture", "--path", "/a", "--action", "allow", "--port", "0"],
                 ["add", "--key", "fixture", "--path", "/a", "--action", "allow", "--port", "0443"],
                 ["add", "--key", "fixture", "--path", "/a", "--action", "allow", "--addr", "[", "--regex"],
                 ["delete-match", "--key", "fixture"], ["delete-match", "--key", "fixture", "--action", "typo"],
                 ["list", "one", "extra"], ["recent", "-1"], ["recent", "bad"], ["help", "extra"],
                 ["disable", "--key", "fixture", "--uuid", "fixture-0", "--bogus"]]
        for args in cases:
            with self.subTest(args=args):
                result = run("--file", path, *args)
                self.assertGreater(result.returncode, 0, args)
                self.assertEqual(digest(path), before, args)

    def test_invalid_archive_never_changes_file(self):
        path = self.fixture("modern")
        archive = plistlib.loads(path.read_bytes())
        obj = next(x for x in archive["$objects"] if isinstance(x, dict) and "isEndpointAddrRegex" in x)
        archive["$objects"].append(7)
        obj["isEndpointAddrRegex"] = plistlib.UID(len(archive["$objects"]) - 1)
        path.write_bytes(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY, sort_keys=False))
        before = digest(path)
        result = run("--file", path, "disable", "--key", "fixture", "--uuid", "fixture-0")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(digest(path), before)

    def test_numeric_root_key_rejected_without_crash(self):
        path = self.fixture("modern")
        archive = plistlib.loads(path.read_bytes())
        objects = archive["$objects"]
        root = objects[archive["$top"]["root"].data]
        objects.append(7)
        root["NS.keys"][0] = plistlib.UID(len(objects) - 1)
        path.write_bytes(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY, sort_keys=False))
        before = digest(path)
        for args in (["list"], ["recent"], ["disable", "--key", "fixture", "--uuid", "fixture-0"]):
            result = run("--file", path, *args)
            self.assertGreater(result.returncode, 0)
            self.assertEqual(digest(path), before)

    def test_unsupported_class_never_writes(self):
        path = self.fixture("modern")
        archive = plistlib.loads(path.read_bytes())
        cls = next(x for x in archive["$objects"] if isinstance(x, dict) and x.get("$classname") == "Rule")
        cls["$classname"] = "UnsupportedFixtureRule"
        path.write_bytes(plistlib.dumps(archive, fmt=plistlib.FMT_BINARY, sort_keys=False))
        before = digest(path)
        result = run("--file", path, "disable", "--key", "fixture", "--uuid", "fixture-0")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(digest(path), before)

    def test_valid_regex(self):
        path = self.fixture("modern")
        result = run("--file", path, "add", "--key", "fixture", "--path", "/fixture/app", "--action", "allow", "--addr", "^example[.]com$", "--port", "443", "--regex")
        self.assertEqual(result.returncode, 0, result.stderr)
        added = [v for k, v in rules(path).items() if not k.startswith("fixture-")]
        self.assertEqual(len(added), 1)
        self.assertEqual(added[0]["isEndpointAddrRegex"], 1)
        self.assertEqual(added[0]["endpointAddr"], "^example[.]com$")

    def test_help_and_unknown(self):
        self.assertEqual(run("--help").returncode, 0)
        unknown = run("not-a-command")
        self.assertGreater(unknown.returncode, 0)
        self.assertIn("Unknown", unknown.stderr)

    def test_backup_contents_and_mode(self):
        path = self.fixture("modern")
        path.chmod(0o600)
        before = path.read_bytes()
        result = run("--file", path, "disable", "--key", "fixture", "--uuid", "fixture-0")
        self.assertEqual(result.returncode, 0, result.stderr)
        backups = list(path.parent.glob("." + path.name + ".backup.*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), before)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)
        self.assertNotEqual(path.read_bytes(), before)

    def test_final_symlink_refused(self):
        path = self.fixture("modern")
        before = digest(path)
        link = path.parent / (path.name + ".link")
        link.symlink_to(path)
        result = run("--file", link, "disable", "--key", "fixture", "--uuid", "fixture-0")
        self.assertGreater(result.returncode, 0)
        self.assertEqual(digest(path), before)
        self.assertEqual(list(path.parent.glob("." + link.name + ".backup.*")), [])

    def test_lock_busy_does_not_write(self):
        path = self.fixture("modern")
        before = digest(path)
        lock = Path(str(path) + ".lulu-cli.lock")
        fd = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = run("--file", path, "disable", "--key", "fixture", "--uuid", "fixture-0")
        finally:
            os.close(fd)
        self.assertGreater(result.returncode, 0)
        self.assertIn("busy", result.stderr)
        self.assertEqual(digest(path), before)
        self.assertEqual(list(path.parent.glob("." + path.name + ".backup.*")), [])

    def test_parallel_writers_never_lose_success(self):
        path = self.fixture("modern")
        args = [str(CLI), "--file", str(path), "add", "--key", "fixture", "--path", "/fixture/app", "--action", "allow"]
        processes = [subprocess.Popen(args + ["--addr", host], stdout=subprocess.PIPE, stderr=subprocess.PIPE) for host in ("one.example", "two.example")]
        results = [p.communicate(timeout=20) or p.returncode for p in processes]
        self.assertTrue(all(p.returncode in (0, 1) for p in processes))
        success = sum(p.returncode == 0 for p in processes)
        self.assertGreaterEqual(success, 1)
        actual = [v for k, v in rules(path).items() if not k.startswith("fixture-")]
        self.assertEqual(len(actual), success)
        self.assertEqual(len(list(path.parent.glob("." + path.name + ".backup.*"))), success)

    def test_declined_mutations_create_no_backup(self):
        path = self.fixture("unknown")
        before = digest(path)
        self.assertNotEqual(run("--file", path, "disable", "--key", "fixture", "--uuid", "fixture-0").returncode, 0)
        self.assertNotEqual(run("--file", path, "add", "--key").returncode, 0)
        self.assertEqual(digest(path), before)
        self.assertEqual(list(path.parent.glob("." + path.name + ".backup.*")), [])

    def test_fifo_rejected_without_hanging(self):
        path = self.tmp_path / "fifo.plist"
        os.mkfifo(path, 0o600)
        for args in (["list"], ["recent"], ["disable", "--key", "x", "--uuid", "y"]):
            with self.subTest(args=args):
                result = subprocess.run([str(CLI), "--file", str(path), *args], capture_output=True, timeout=1)
                self.assertGreater(result.returncode, 0)
        self.assertTrue(stat.S_ISFIFO(path.lstat().st_mode))
        self.assertEqual(list(path.parent.glob("." + path.name + ".backup.*")), [])

    def test_oversized_archive_rejected(self):
        path = self.tmp_path / "oversized.plist"
        with path.open("wb") as stream:
            stream.truncate(64 * 1024 * 1024 + 1)
        before = path.stat().st_size
        result = run("--file", path, "list")
        self.assertGreater(result.returncode, 0)
        result = run("--file", path, "disable", "--key", "x", "--uuid", "y")
        self.assertGreater(result.returncode, 0)
        self.assertEqual(path.stat().st_size, before)
        self.assertEqual(list(path.parent.glob("." + path.name + ".backup.*")), [])

    def test_reload_unavailable(self):
        result = run("reload")
        self.assertGreater(result.returncode, 0)
        self.assertIn("unsupported", result.stderr)

    def test_global_flags_and_offline_guards(self):
        path = self.fixture("modern")
        self.assertEqual(run("--offline", "--file", path, "list").returncode, 0)
        self.assertEqual(run("--file", path, "--offline", "list").returncode, 0)
        self.assertGreater(run("--offline", "--offline", "list").returncode, 0)
        self.assertGreater(run("--file", path, "--file", path, "list").returncode, 0)
        self.assertGreater(run("add", "--key", "x", "--path", "/x", "--action", "allow").returncode, 0)

    def test_pure_permissions_and_generation_checks(self):
        source = (ROOT / "Sources/LuLuCLI/main.swift").read_text().split("var commandArguments =", 1)[0]
        path = self.fixture("modern")
        harness = source + "\nfunc captureLogProcess(_ process: Process, timeout: TimeInterval, limit: Int) throws -> Data { return Data() }\n" + r"""
        let path = CommandLine.arguments[1]
        do { try checkMutationPermission(system: true, offline: false, uid: 0, checkStopped: {}); exit(3) } catch {}
        do { try checkMutationPermission(system: true, offline: true, uid: 501, checkStopped: {}); exit(4) } catch {}
        do { try checkMutationPermission(system: true, offline: true, uid: 0, checkStopped: { throw MutationError.message("active") }); exit(5) } catch {}
        do { try checkMutationPermission(system: true, offline: true, uid: 0, checkStopped: {}) } catch { exit(6) }
        let (before, info) = try snapshot(path)
        guard chmod(path, 0o640) == 0 else { exit(8) }
        do { try requireUnchanged(path, data: before, identity: FileIdentity(info)); exit(9) } catch {}
        try Data("changed".utf8).write(to: URL(fileURLWithPath: path))
        do { try requireUnchanged(path, data: before, identity: FileIdentity(info)); exit(7) } catch {}
        """
        script = self.tmp_path / "guards.swift"
        script.write_text(harness)
        result = subprocess.run(["swift", str(script), str(path)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(path.read_bytes(), b"changed")

    def test_profile_path_validation(self):
        source = (ROOT / "Sources/LuLuCLI/main.swift").read_text().split("var commandArguments =", 1)[0]
        root = self.tmp_path / "profile root"
        (root / "Profiles/good").mkdir(parents=True, exist_ok=True)
        (root / "outside").mkdir(exist_ok=True)
        (root / "Profiles/escape").symlink_to(root / "outside", target_is_directory=True)
        (root / "Profiles/badfile").mkdir(exist_ok=True)
        (root / "Profiles/badfile/rules.plist").symlink_to(root / "outside/rules.plist")
        harness = source + "\nfunc captureLogProcess(_ process: Process, timeout: TimeInterval, limit: Int) throws -> Data { return Data() }\n" + r"""
        let root = URL(fileURLWithPath: CommandLine.arguments[1]).resolvingSymlinksInPath().path
        precondition((try? rulesPathForProfile(nil, root: root)) == root + "/rules.plist")
        precondition((try? rulesPathForProfile("", root: root)) == root + "/rules.plist")
        precondition((try? rulesPathForProfile(root + "/Profiles/good", root: root)) == root + "/Profiles/good/rules.plist")
        precondition((try? rulesPathForProfile("good", root: root)) == nil)
        precondition((try? rulesPathForProfile(root + "/Profiles/escape", root: root)) == nil)
        precondition((try? rulesPathForProfile(root + "/Profiles/badfile", root: root)) == nil)
        precondition((try? rulesPathForProfile(root + "/outside", root: root)) == nil)
        """
        script = self.tmp_path / "profile.swift"
        script.write_text(harness)
        result = subprocess.run(["swift", str(script), str(root)], capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
