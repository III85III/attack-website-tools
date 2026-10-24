# Qolam Sentinel 0.18.0

## Browser-confirmed reflected XSS

Deep scans now attempt browser execution confirmation for up to three native raw-HTML reflection candidates. Playwright drives a signed system Edge/Chrome with a fresh anonymous context, sandbox and TLS checks enabled. A benign SVG event handler computes a random expected value in the main document. The evaluator only reads that property. Only a matching observed result in a successful response becomes HIGH / CONFIRMED / VALIDATED; account-specific impact and Critical severity are not inferred.

Missing browsers, certificate errors, CSP blocking, encoded payloads, redirects and timeouts remain inconclusive. There is no assertion that an unconfirmed candidate is safe. Stored/blind XSS, exhaustive DOM analysis, POST inputs and authenticated XSS are not covered. The browser does not load personal profiles or supplied-session credentials. Bounded same-origin GET routing blocks mutations, redirected requests and external assets; no browser is downloaded. Browser GET attempts are logged separately from the native HTTP counter.

Word reports include browser coverage, the affected parameter, benign payload, browser version and matching expected/observed proof in the finding evidence. Existing session/access review, import integrations and Word/JSON exports remain available.

The new application icon is an original code-drawn obsidian shield with a luminous infinity mark. OPEN SENTINEL.exe in the project root launches this version's portable EXE without a command window. Its C# source is included. Keep the full portable folder and its _internal directory together. Browser shutdown is bounded using only the disposable browser process verified as a child of the scanner; existing personal browsers are not selected.

Verification results are recorded in release/VERIFICATION_0.18.0.json. Public targets are not used during QA. This remains an unsigned release candidate with the stable-release gates in RELEASE_CHECKLIST.md outstanding.

Primary API references: https://playwright.dev/python/docs/api/class-browsercontext and https://playwright.dev/python/docs/api/class-browsertype .
