# Desktop packages

Version 0.20.0 introduces native Linux and macOS packages alongside Windows.
Only packages that pass the complete source suite and frozen-app checks are
eligible for the GitHub release. Consult each asset's verification JSON.

| Package | Build and verification host | Launch after extraction |
|---|---|---|
| Windows x64 ZIP | GitHub Windows x64 | `app/Qolam_Sentinel.exe` |
| Linux x64 tar.gz | GitHub Ubuntu 24.04 x64 | `./app/Qolam_Sentinel` |
| macOS arm64 tar.gz | GitHub macOS 15 Apple Silicon | `ATTACK WEBSITE TOOLS.app` |
| macOS x64 tar.gz | GitHub macOS 15 Intel | `ATTACK WEBSITE TOOLS.app` |

The archives include the runtime, matching GPL application source, upstream
licenses, a build manifest and checksums. Keep the entire extracted folder.
Python is not required. Linux requires a graphical desktop and compatible
system libraries; this is not a headless server service or a universal Linux
binary. Older macOS versions and other Linux distributions are not verified.

## macOS

Choose arm64 for Apple Silicon (M-series), or x64 for Intel. Extract with Archive
Utility or `tar -xzf <downloaded-file>.tar.gz`, then open the application bundle.
The release is not Developer ID signed or notarized. macOS or an organization's
policy may prevent launching downloaded unsigned apps. There is no claim of
Gatekeeper approval; do not disable platform protections to run this build.
CI launch checks do not reproduce every first-download security prompt.

## Linux

Extract the tar.gz with `tar -xzf <downloaded-file>.tar.gz` and run the binary
inside the extracted `app` directory. The archive preserves executable modes
and runtime symlinks. Use a normal desktop account, not root. Ubuntu 24.04 is
the baseline. If the loader reports missing GUI libraries, install the relevant
distribution packages, such as `libegl1`, `libopengl0`, `libxcb-cursor0` and
`libxkbcommon-x11-0`. Exact requirements depend on the desktop environment.

## Browser confirmation

- Windows: fixed-location Edge/Chrome with a valid vendor Authenticode signature.
- macOS: system-wide Chrome/Edge in `/Applications`, with strict Apple signature
  validation and a matching vendor identifier and signing team.
- Linux: fixed-location Chrome/Edge/Chromium owned by the expected dpkg/rpm
  package, with root ownership and no group/world-writable binary or ancestors.
  Package ownership is not a fresh cryptographic integrity audit. Snap wrappers
  and arbitrary PATH browsers are not accepted.

The browser remains sandboxed, anonymous, bounded and restricted to the target
origin. Missing browser support is reported as unavailable; it is never a
successful XSS check. No browser is downloaded automatically.

## Platform-specific features and data

Website/API review, supplied-session checks, report imports, Word/JSON export,
and optional Nmap/ZAP integration share the same application code. Install
optional tools separately. Windows Defender and Windows speech playback are
Windows-specific; they are not provided as native macOS/Linux services.

User data is outside the installation folder:

- Windows: `%LOCALAPPDATA%/III85III/Qolam Sentinel` (existing portable Windows data is preserved).
- macOS: `~/Library/Application Support/III85III/Attack Website Tools`.
- Linux: `${XDG_DATA_HOME:-~/.local/share}/iii85iii/attack-website-tools`.

Cross-platform builds verify real loopback requests, Word generation/reopening,
JSON export, SQLite persistence and construction of the scanner window. These
are automated checks, not a completed interactive desktop or Word layout audit.
All 0.20.0 packages remain release candidates and are not vendor-signed releases.
