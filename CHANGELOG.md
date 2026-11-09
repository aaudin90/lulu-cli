# Changelog

## Unreleased

- Support LuLu 4.5.7 archive address-match types, legacy encodings, active profiles, and offline `--file` archives.
- Reject unknown rule fields on writes and malformed CLI arguments before archive access.
- Add `logs` for bounded LuLu unified-log inspection.
- Require root, `--offline`, and a stopped LuLu application and extension for system archive writes.
- Lock cooperating writers and create verified backups before atomic replacement.
- Disable forced live `reload`; start LuLu normally after an offline change.


## 0.1.0

- Initial release
- Commands: list, recent, add, delete, delete-match, enable, disable, reload
- Supports regex address patterns
- Direct plist read/write using NSKeyedArchiver format
