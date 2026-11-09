---
name: lulu-cli
description: Inspect LuLu 4.5.7 firewall rule archives and logs with lulu-cli. Use when asked to inspect an existing LuLu setup or a separate rules archive.
---

# LuLu CLI

Use `lulu-cli --help` for syntax. `lulu-cli --file PATH list` reads a separate archive; the global `--file` option precedes the command. Without it, the active LuLu profile is selected from the default preferences. Archive reads support legacy address types and LuLu 4.5.7 numeric exact, regex, CIDR and glob values. Unknown `Rule` fields prevent writes.

`lulu-cli logs --last 5m --limit 200 --json` reads unified log events. `--last` accepts a duration up to seven days; `--process` filters an exact path; `--limit` is 1–10000. Logs may lack the application PID and protocol. A missing event does not prove that no connection occurred.

Validate parameters before acting. `delete-match` requires a filter and `delete --key KEY` without `--uuid` removes all rules for that key. `--regex` treats `--addr` as a regular expression. Ports are `*` or 1–65535. Do not create global allow rules as a diagnostic shortcut.

Writes to user-owned `--file` archives require a caller-owned parent directory that is not writable by others. Each successful write creates a verified sibling backup and replaces the archive atomically under a per-file lock. Other programs may not honor that lock.

System archive writes require root. Live writes are allowed. After replacement, disk contents are checked at +0, +1, and +3 seconds. These checks do not prove LuLu loaded or applied the rules, and another writer can change the file later. If verification fails, the write already happened and the backup remains; inspect the file before any retry. `reload` is unsupported and does not kill any process. Write system rules only with the user's instruction.

LuLu can group Developer ID executables by signing identifier and authority, so rules may apply to multiple paths sharing that identity. Inspect the actual identity and scope before writing.
