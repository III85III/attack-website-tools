# Verification evidence

The JSON records local Windows verification before publication. Its `published: false` field describes that point in time.

- 227 source tests passed.
- Five packaged API cases verified real DOCX generation/reopening, persistence and JSON export.
- Three browser cases distinguished executing XSS from CSP-blocked and encoded input.
- Four session cases checked access expectations and incomplete authentication coverage.
- Actual request counts were compared with disposable loopback server counts.

These checks do not establish an independent audit, clean-machine compatibility, completed visual Word review or exhaustive vulnerability coverage.
