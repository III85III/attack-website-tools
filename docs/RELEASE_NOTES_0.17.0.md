# Qolam Sentinel 0.17.0

## Supplied sessions and declared access checks

Scanner adds an optional Session / access setup dialog. Supply a primary test account's Cookie request-header value or Bearer token, an account-identifying read-only page and unique non-secret identifying text. An optional second test account needs a separate session and distinct identifying text. Values remain in application memory; they are not settings, command-line arguments or report fields in the GUI workflow. Clear setup or close the app when finished.

Configure up to twelve explicit same-origin read-only paths, unique content markers, expected anonymous/second-account access, and optional forbidden content in the primary response. The whole plan is checked before credentials are sent. Remote targets require HTTPS; only loopback permits HTTP for local testing. Redirects are not followed. No login attempts, password guessing, form submissions, resource-ID enumeration or state-changing methods are added. The assessor must confirm the supplied GET paths are actually read-only.

The canary must return a successful response with the supplied identifying text. HTTP 200 without that text does not validate a session. Unusable or expired sessions, unreadable/capped bodies, missing expected content and redirects produce inconclusive coverage. Denied comparisons require a matching primary baseline. Explicitly denied identities that receive the protected marker create scanner-reported access findings; role assignment and impact still require assessor review. Anonymous cookie jars are cleared between route checks. The review issues at most 38 GET attempts, reads at most 250,000 bytes per response and delays between requests.

The optional forbidden-content assertion checks a declared read-only business expectation. A failure is a low-severity potential issue, not proof of a transaction exploit. Purchase/refund flows, MFA, login/password-reset behavior, stored/DOM XSS, unlisted resources and full business workflows are not automatically covered. Credentials are not forwarded to ZAP or Nmap. The ordinary bounded unauthenticated scan and existing engine integration remain available.

## Evidence and presentation

Session/access runs are linked child assessments. Word and JSON retain their checks and actual GET counts. Reports store status codes, outcomes and body hashes, not request credentials, response bodies or identifying marker text. A coverage section explains missing manual review. Word separates evidence status from severity and explicitly states that native reflected-input findings have not verified browser script execution, even if a reviewer changes a finding's status label.

The scanner landing page hides the empty results grid, uses a cleaner call to action and adds a code-drawn glow/dot field to its infinity visual. Idle animation remains stopped. A report-without-scan metadata crash was also fixed.

## Verification and remaining scope

Local tests use synthetic accounts on disposable loopback targets. Versioned verification records the actual suite, packaged runtime and archive checks. No public site was tested or uploaded. This does not claim parity with Invicti or complete detection of Critical flaws. Native XSS currently detects inert-marker reflection; it has no browser execution validator.

Primary design references: [OWASP authorization testing](https://owasp.github.io/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/05-Authorization_Testing/02-Testing_for_Bypassing_Authorization_Schema), [OWASP business logic testing](https://wstg.owasp.org/stable/4-Web_Application_Security_Testing/10-Business_Logic_Testing/), and [Invicti's explanation of XSS validation](https://www.invicti.com/xss-scanner). References describe testing principles; Sentinel implements only the subset stated above.
