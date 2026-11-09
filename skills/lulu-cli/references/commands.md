# Commands

See `lulu-cli --help` for current syntax. Put `--file PATH` before the command to select a separate archive. Without it the active profile is selected from LuLu preferences.

- `list [filter]`: inspect rule match types and endpoints.
- `recent [N]`: inspect the most recent block rules; this is not an event log.
- `logs [--last DURATION] [--process PATH] [--limit N] [--json]`: inspect LuLu unified-log events. Duration is up to seven days, limit is 1–10000, and process is an exact path. Records may omit application PID and transport.
- `add --key KEY --path PATH --action allow|block [--addr ADDR] [--port PORT] [--regex]`.
- `delete --key KEY [--uuid UUID]`: omitting UUID deletes all rules for KEY.
- `delete-match --key KEY [--action allow|block] [--addr ADDR] [--port PORT]`: requires at least one explicit filter.
- `enable` / `disable`: require `--key` and `--uuid`.
- `reload`: unsupported; it does not stop the extension.

Archive writes lock cooperating CLI writers and create verified sibling backups. Other programs may not honor the lock. System archive writes require root, `--offline`, and a stopped LuLu application and extension until the write finishes. Use an isolated, user-owned copy for testing. Unknown Rule fields prevent writing. `--addr` defaults to `*`; `--port` accepts `*` or 1–65535. Never infer coverage of live traffic from an archive edit or missing log events.

LuLu may group Developer ID binaries by their signing identifier and authority, so multiple paths can share rules. `recent` describes rules; `logs` describes available events.
