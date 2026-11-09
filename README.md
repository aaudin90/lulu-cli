# lulu-cli

Command-line inspection and management of [LuLu](https://objective-see.org/products/lulu.html) archives on macOS. This fork targets LuLu 4.5.7. Build from this repository; upstream releases do not include these changes.

```sh
git clone --branch fix/lulu-4-5-compatibility git@github.com:aaudin90/lulu-cli.git
cd lulu-cli
swift build -c release
.build/release/lulu-cli --help
```

`--file PATH` before the command selects a separate archive for offline work. Without it, the CLI uses the active LuLu profile from `/Library/Objective-See/LuLu/preferences.plist`; only direct children of `Profiles` are accepted. The default profile uses the top-level `rules.plist`.

```sh
lulu-cli --file /path/to/copy.plist list
lulu-cli --file /path/to/copy.plist recent 20
lulu-cli logs --last 5m --limit 200 --json
```

Archive decoding preserves LuLu address-match types: exact, regex, CIDR, and glob. It reads legacy primitive encodings and writes match types as numeric objects. Unknown `Rule` fields produce a warning during read and prevent modification. `logs` inspects LuLu unified log events; log records may not contain an application PID or transport protocol. Do not treat missing records as proof of absence.

Use `--help` for command arguments. Options require values, ports must be `*` or 1–65535, and actions are `allow` or `block`. `delete-match` requires an explicit filter; `delete --key KEY` without `--uuid` deletes all rules for that key.

Writes to a user-owned archive selected with `--file` do not require root. Its parent directory must be owned by the caller and not writable by others. Reads and writes require a regular file no larger than 64 MiB; a final-component symlink is rejected. A successful write creates a verified sibling backup, keeps file metadata, and atomically replaces the archive. A per-file lock serializes cooperating CLI writers; a changed source aborts the operation. Other writers do not honor this lock, so they still require coordination.

Writes to archives under `/Library/Objective-See/LuLu` require root and normal filesystem permissions. Live file writes are allowed. After replacement, the CLI compares the complete disk contents immediately, at +1 second, and at +3 seconds. It releases its lock before these checks. They do not verify that LuLu loaded the rules or that traffic follows them, and LuLu or another writer may change the file after the checks.

If verification fails, the command reports that the write already happened and retains the backup. Inspect the file before deciding what to do; the CLI does not automatically roll back or retry. `reload` is unsupported and never kills the extension.

LuLu may group Developer ID binaries using a signing identifier and signing authority. Two paths with the same signing identity can share rules; inspect identity and scope before editing. `recent` lists block rules, while `logs` reports persisted events where available.

Run local checks with `swift build -c release` and `python3 -m unittest discover -s Tests -p test_cli.py`.
