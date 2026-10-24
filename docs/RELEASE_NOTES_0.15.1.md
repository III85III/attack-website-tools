# Qolam Sentinel 0.15.1

## Background report import

Findings and Tool Integrations now share a background import control. File parsing and SQLite writes run in a worker thread, leaving the GUI event loop available. The import button is disabled while working; a second start cannot replace the running worker. The inline status displays imported finding count, source tool, assessment status and partial-import messages.

The application refuses to close while an import is still running, using the same worker check as scans and exports. No forced thread termination or import cancellation is provided.

## Atomic persistence

An imported assessment and all its findings now commit in one transaction. Parsing failures save no assessment. Storage failures roll back the new scan and its findings. Other assessment storage methods retain their transaction behavior. Worker database connections close on completion.

The previous UI path saved the scan and then committed each finding separately on the GUI thread. A failure could leave a successful-looking assessment containing only the earlier findings. This update removes that path from both import pages.

## Verification scope

Tests exercise a blocked background parser released by a GUI timer, verify parsing runs on another thread, prevent duplicate starts, check saved results, force a write failure after the first finding and verify rollback, reject cross-assessment rows, and check parser/database-open errors. See VERIFICATION_0.15.1.json for the actual suite and packaged runtime results.

No additional external scanner was launched. Source-report coverage remains unverified. The local release remains a candidate; clean Windows validation, Word visual review, signing, support details and dependency licensing review remain open.
