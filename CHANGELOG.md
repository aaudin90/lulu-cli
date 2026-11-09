# Changelog

## Unreleased

- Support LuLu 4.5.7 archive address-match types, legacy encodings, active profiles, and offline `--file` archives.
- Reject unknown rule fields on writes and malformed CLI arguments before archive access.
- Add `logs` for bounded LuLu unified-log inspection.
- Require root for system archive writes; LuLu can remain running.
- Lock cooperating writers and create verified backups before atomic replacement.
- Verify written disk bytes at +0, +1, and +3 seconds; report failed checks as post-commit failures.
- Disable forced live `reload`.


## 0.1.0

- Initial release
- Commands: list, recent, add, delete, delete-match, enable, disable, reload
- Supports regex address patterns
- Direct plist read/write using NSKeyedArchiver format
