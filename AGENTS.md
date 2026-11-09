# AGENTS.md

Instructions for AI coding agents working on this codebase.

## Overview

Swift CLI that reads/writes LuLu's `rules.plist` (NSKeyedArchiver binary format). macOS only.

## Build

```bash
make build          # swift build -c release
make install        # build + copy to ~/.local/bin/
make clean          # swift package clean
```

## Project Structure

```
Sources/LuLuCLI/main.swift    # Archive handling and command dispatch
Sources/LuLuCLI/Logs.swift    # Bounded unified-log queries and parsing
Tests/                       # Synthetic archive and log regression tests
Package.swift                  # SwiftPM manifest
Makefile                       # Build/install interface
skills/lulu-cli/               # AI agent skill
```

## Code Style

- Keep archive handling in main.swift and unified-log handling in Logs.swift.
- CLI flags use `--kebab-case`.
- Error output goes to stderr (`fputs(..., stderr)`), normal output to stdout (`print`).
- System archive writes require root. User-owned archives and read operations do not require root.

## Testing

Build first, then run the synthetic regression tests without sudo:

```sh
make build
python3 Tests/test_cli.py
swiftc Sources/LuLuCLI/Logs.swift Tests/LogsTests.swift -o /tmp/lulu-log-tests
/tmp/lulu-log-tests
```

Use temporary archives with `--file` for mutation tests. Real system archives are suitable for read-only smoke tests. Verify actual filter decisions separately with the user's authorized network tests.

## Key Implementation Details

- The `Rule` class mirrors LuLu's Objective-C `Rule.m` with NSSecureCoding.
- Rules are stored in an NSKeyedArchiver binary plist at `/Library/Objective-See/LuLu/rules.plist`.
- `reload` is unsupported and never kills the system extension.
- Live system archive writes require root; no LuLu stop is required. Verify disk contents at +0, +1, and +3 seconds after replacement. These checks do not prove LuLu loaded the rules, and other writers can change the file later. A verification failure means the write already happened; inspect before retrying.
- Writes use a per-file lock, verified sibling backup, and atomic replacement. Other programs may not honor the lock.
- LuLu groups some signed binaries by signing identifier and authority; paths with the same identity may share rules.

## PR Guidelines

- Update `skills/lulu-cli/SKILL.md` if commands or flags change.
- Update `README.md` with any user-facing changes.
- Test on macOS with LuLu installed before submitting.
