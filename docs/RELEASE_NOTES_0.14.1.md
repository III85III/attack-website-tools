# Qolam Sentinel 0.14.1

## Prevent misleading clean results from ZAP

An HTTP 200 response from ZAP is no longer sufficient to accept the alert collection. API error objects, missing alerts arrays, invalid roots and malformed alert records are rejected. Only an explicit valid `alerts: []` represents an empty result. The active-scan pipeline records a failure when alert collection is invalid and still removes its temporary context.

## Protect exported assessment data

- Word now filters all finding, scan, target and report fields, not only the raw evidence cell.
- JSON export filters the complete exported payload.
- A shared filter masks full Basic/Bearer authorization and cookie header values, common secret assignments, JWTs, URL user information and common credential query parameters.
- Structured execution logs and external report import use the same filter.
- ZAP alert evidence is filtered before normalization/storage. Exports of existing records operate on copies and do not alter stored source findings.

Redaction remains heuristic. Review the complete report before sharing it. Existing database records are not rewritten or deleted by this update.

## Regression evidence

The former behavior was reproduced with invalid ZAP payloads and test credentials in alternate finding fields, raw headers, URLs and structured logs. Coverage distinguishes an explicit empty alert list from an API error, exercises the ZAP pipeline cleanup path, checks Word/JSON/log output, and verifies that ordinary Basic-authentication prose and non-secret evidence survive filtering.

See the versioned verification JSON beside the release artifacts for observed suite, packaged runtime and archive checks. The release is prepared locally; no external target scan or public upload was performed.
