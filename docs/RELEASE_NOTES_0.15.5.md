# Qolam Sentinel 0.15.5

## Initial response coverage

An initial response outside HTTP 200 through 299 now makes the assessment PARTIAL when collection otherwise succeeds. A redirect explains that the destination was not followed or assessed and asks for its authorized URL as a separate assessment. Initial HTTP 401/403 responses explain that protected application coverage was not established. Other non-success initial responses explain that normal application content coverage was not established.

The actual received status, request count, collected findings and header observations remain available. A collection failure still takes priority as FAILED. Successful initial response codes are not marked partial by status alone. A completed bounded review remains no guarantee of security, authenticated coverage or full penetration testing.

Only the initial response has this additional status policy. Missing sensitive-file probes commonly return non-success responses; those alone do not imply a failed assessment. Redirects remain disabled, and Sentinel does not store or contact a redirect destination from the Location header.

## Reports and pipeline

Word and JSON retain the completion reason. The execution log adds initial_response_coverage_limited and initial_response_limitation. Existing partial-assessment handling preserves the status and stops before optional engines when required HTTP collection is incomplete.

Controlled tests cover initial 301, 302, 401, 403, 404, 429, 500 and 503 responses; confirm redirect destinations are not requested or retained in assessment metadata; verify Word/JSON limitations; and retain completed behavior for successful status fixtures. See VERIFICATION_0.15.5.json for the observed suite and packaged loopback checks. No public target was scanned, no external scanner was launched for verification and nothing was uploaded. Prior artifacts are preserved; stable-release gates remain open.
