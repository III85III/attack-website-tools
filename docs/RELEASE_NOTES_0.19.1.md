# Qolam_Hacker 0.19.1 — evidence and coverage upgrade

- One primary **Scan Website** action. Deep website review, available engines and bounded API discovery run automatically. Right-click Scan for optional supplied-session and OpenAPI setup; these are setup operations, not scan modes.
- Bounded application map connects pages, forms, scripts, literal API routes and source maps with discovery provenance. Query values are redacted. Discovery is separate from successful collection.
- JavaScript analysis excludes comments and literal strings, follows supported statement-level aliases, kills stale taint on reassignment and abstains across unsupported scopes. Findings remain static candidates; this is not a complete JavaScript AST or runtime analysis.
- Source maps require parsed v3 structure, including sources and mappings. Actual sourceMappingURL references are resolved within the target origin. Source bodies and candidate secret values are not copied into evidence.
- CORS reflection requires two unpredictable origins. HEAD/GET status differences remain low-severity policy leads and never establish authentication bypass.
- Template evaluation requires two independently generated benign arithmetic challenges. Fixed example output and raw reflection are insufficient.
- Session canaries are checked against an anonymous control and the other account marker. Denied-resource matches are repeated; the second account identity is revalidated. Responses cannot silently change identities through cookies.
- No automatic adjacent-object ID guessing, fabricated REST-to-query conversion, server-loopback SSRF requests or method-override POST. Those scenarios require explicitly declared accounts/resources or approved infrastructure. Coverage gaps remain visible.
- API discovery closes responses, caps input and records attempts. Parent request counts include API discovery, API review and session review, while browser requests remain separate.
- Provider-shaped tokens and unsigned JWTs are redacted before native UI/storage and export. Imported findings are also sanitized at the storage boundary.

Word, HTML, Markdown and JSON use the existing reporting pipeline. Existing report fields and integrations are preserved. See DEPTH_COVERAGE_AUDIT.md for code references, verification and limitations.
