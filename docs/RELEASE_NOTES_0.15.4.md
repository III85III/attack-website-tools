# Qolam Sentinel 0.15.4

## Distinguish headers from complete body collection

An initial HTTP response whose body raises a Requests collection exception is now FAILED even when its headers supplied HTTP 200. The received status and actual request count remain in the assessment. Previously the presence of an HTTP status could incorrectly allow COMPLETED after initial body collection failed.

Errors during later bounded collection now produce PARTIAL. Error type names are recorded without exception message secrets. A follow-up Requests exception is counted once rather than both in the request helper and its sensitive-file caller.

## Disclose body limits

Reaching the 1,000,000-byte response body limit now produces PARTIAL and records the configured byte limit and number of limit hits. It does not generate a vulnerability finding. The completion reason exposes the coverage limitation in the scanner and exported Word/JSON assessment.

A response that ends exactly at the limit is conservatively marked as a limit hit. The scanner stops reading at the cap and cannot establish whether more content remained; it does not send another request or read beyond the cap to resolve that uncertainty. Body read error counts are also recorded in the execution log.

## Pipeline and evidence

The existing pipeline stop rule for a non-completed required HTTP assessment remains in force. Its log now preserves the actual PARTIAL or FAILED state and explains that optional engines were not started. The UI's partial-coverage explanation now covers collection limits as well as optional-engine errors.

Controlled fixtures cover initial HTTP 200 with a broken stream, later broken streams, oversized and exact-limit bodies, closure of the response, Word/JSON coverage details, no-response failure and persistence of a partial pipeline result. See VERIFICATION_0.15.4.json for actual tests and packaged loopback evidence. No public target or external scanner was run for this verification. Prior artifacts are preserved; the release remains a local candidate.
