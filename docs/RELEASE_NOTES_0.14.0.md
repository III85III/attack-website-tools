# Qolam Sentinel 0.14.0

## Assessment integrity

- Finalizing a scan now updates its SQLite row in place. The former `INSERT OR REPLACE` could null finding-to-scan links through the foreign key's delete action.
- Optional ZAP/Nmap engine runs carry their parent assessment ID. Exports combine the selected assessment and those engine runs.
- Both Word and JSON export one explicit assessment. JSON previously combined the latest scan's metadata with findings from other targets.
- Report exports include all saved findings in that assessment; display row caps do not truncate the report.
- Repeated JSON exports receive distinct filenames.

Existing findings whose links were already lost remain in Findings. Their original assessment is not guessed or reassigned automatically.

## Scanner experience

- One URL and one scan action, a compact infinity activity mark, severity counts, and visible completion/coverage details.
- Double-click a finding for its full description, confidence, evidence and remediation.
- Export Word/JSON directly below scan results. Open the report or its folder when ready.
- Report creation runs on a background worker. Reports history now selects a specific saved assessment.
- Duplicate starts are blocked; the window stays open while a scan or report worker is running.
- The animation stops when idle or hidden. Dark alternate table rows and plain navigation labels improve readability.
- The EXE includes the application's own icon. Runtime caches are excluded from the build.

## Release artifacts

The portable folder keeps the EXE at its root. `package_release.py` includes matching application source, collected upstream dependency licenses, an installed dependency manifest and per-file hashes. The portable ZIP and standalone source ZIP have SHA-256 checksums.

## Verification and remaining scope

Regression coverage includes scan finalization, parent/child grouping, target isolation, a report larger than the UI row limit, Word/JSON content, asynchronous UI export, and local HTTP pipeline execution.

See RELEASE_CHECKLIST.md for observed release checks and remaining gates. This is bounded unauthenticated DAST; active integrations require the user's scope confirmation and separately configured tools.
