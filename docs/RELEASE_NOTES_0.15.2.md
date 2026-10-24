# Qolam Sentinel 0.15.2

## Reject malformed imported findings

Generic JSON finding collections now require object rows with a nonempty text title, name, rule or ID. Empty objects no longer become placeholder findings, and non-object rows are no longer silently discarded. An explicit empty findings array remains supported.

SARIF imports validate the supported run, driver, rule properties, results, message and physical-location structures. Unsupported malformed structures produce an import error instead of a runtime attribute error, skipped record or placeholder result. A valid result may omit optional tool and location data. Hydra report arrays also reject non-object records instead of silently removing them; no credential replay is performed.

The existing background import transaction saves no assessment when validation fails. Error messages explain the unsupported structure. This is validation of Sentinel's supported import subset, not a complete SARIF conformance checker.

## Bound numeric severity

Imported numeric security severity contributes to the mapped severity only when it is finite and within 0 through 10. Infinity, NaN, oversized integers, booleans and values outside that range are ignored; the source text severity then applies. An explicit zero score maps to informational, including a SARIF result whose level is error. Positive scores below 4 map to LOW, including 0.1 and 0.9 that previously fell through to the text level. Other supported score ranges retain their mappings. The rating boundaries follow the [FIRST CVSS v3.1 qualitative scale](https://www.first.org/cvss/v3.1/specification-document#Qualitative-Severity-Rating-Scale); Sentinel does not calculate or validate a CVSS vector. Source severity remains scanner-reported and does not establish exploitability.

## Local verification

Regression fixtures cover malformed generic/SARIF/Hydra data, valid optional SARIF fields, invalid numeric values and valid threshold boundaries. Full local suite and packaged runtime evidence are recorded in VERIFICATION_0.15.2.json. No external scanner or public target was executed. Earlier releases are preserved. Public stable-release requirements remain in the release checklist.
