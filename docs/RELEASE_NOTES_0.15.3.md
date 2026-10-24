# Qolam Sentinel 0.15.3

## Background tool availability checks

Tool Integrations now runs its existing detector checks in a worker thread. The page stays available while probes wait, displays the current check, and disables refresh until completion. Repeated refresh requests reuse the running operation. The application waits for background work to finish before closing; this includes health checks.

One detector exception no longer aborts all remaining checks. Its row becomes EXECUTION_FAILED with availability explicitly unknown, and subsequent checks continue. Invalid detector output also becomes a failure rather than an empty successful result. This update does not add scanners or run extra executable probes: the existing built-in, Nmap, Defender, ZAP and PCAP checks and optional PATH/archive inventory are retained.

## Truthful status and storage

Unverified speech synthesis and CISA cache freshness no longer display Ready or Active claims. Their notes say what has not been checked; VERSION_CHECK_FAILED remains the availability status.

Health rows from one refresh are saved in a single transaction. A storage failure rolls back that refresh's writes and leaves prior records intact. The UI can show collected results with an explicit not-saved warning. Worker connections close after use. Saved health records are historical observations, not a continuous readiness monitor.

## Verification

Local fixture tests cover event-loop responsiveness while a probe waits, duplicate-refresh prevention, thread identity, persisted health rows, exception isolation, secret filtering in errors, malformed detector output, transaction rollback and database-open failure. These checks do not establish that optional tools are installed or operational on a clean customer machine. Actual suite, packaged loopback runtime and archive checks appear in VERIFICATION_0.15.3.json. Prior releases are preserved; nothing was published.
