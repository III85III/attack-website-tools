"""Conservative duplicate consolidation without merging different observations."""
import json


def distinct_findings(findings):
    seen, result = set(), []
    for finding in findings:
        record = finding.to_dict()
        for transient in ("id", "timestamp", "scan_id"):
            record.pop(transient, None)
        key = json.dumps(record, sort_keys=True, ensure_ascii=False)
        if key not in seen:
            seen.add(key)
            result.append(finding)
    return result
