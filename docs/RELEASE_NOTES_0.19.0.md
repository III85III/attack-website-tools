# Qolam Sentinel 0.19.0

## Actual API coverage from definitions

Assessment setup now accepts local OpenAPI 3.0/3.1 and Swagger 2.0 JSON. The parser does not execute content or fetch references. A scope-bound plan discovers API routes that an HTML crawl would miss. The live API engine sends bounded anonymous GET requests, checks query inputs using the existing DAST engine and confirms eligible reflected XSS in an isolated signed system browser. Path templates, POST/JSON bodies and unresolved dependencies remain explicitly not tested; no completeness claim is inferred.

Every declared operation is retained in assessment coverage, including exclusions, unsuccessful responses and limit hits. Word/JSON include source SHA-256, response status/hash, HTTP counts and browser counts. A mismatch between declared authentication and successful anonymous content is a potential issue requiring owner-policy validation. Empty security alternatives permit public access. Response cookies are discarded before each API request and no supplied sessions are forwarded. Definition examples/defaults are not submitted or stored.

The unified scanner links API engine runs to the parent assessment; incomplete API coverage does not discard other collected findings or prevent independently configured engines from running. The interface keeps one URL and scan action, with session/API configuration in a single Assessment setup menu. Native probes tolerate unknown response charsets; missing-CSP text now explains that header absence alone does not prove XSS.

The packaged local API diagnostic also creates, reopens and checks a real DOCX through the frozen application's report engine, alongside persistence and JSON export. It is a release QA entry point restricted to loopback, not a restriction on the normal product's authorized public targets.

This is an unsigned release candidate. Verification records actual local tests and packaged runtime evidence. There is no claim of certification for a named institution, exhaustive vulnerability detection, code signing or independent audit.

Primary references: https://spec.openapis.org/oas/v3.0.4.html and https://www.zaproxy.org/docs/desktop/addons/openapi-support/ . Sentinel implements the explicitly documented subset, not all capabilities of those projects.
