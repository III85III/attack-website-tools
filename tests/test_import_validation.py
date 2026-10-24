import json
import pytest

from src.adapters.report_import_adapter import ReportImportAdapter, _severity
from src.core.models import FindingSeverity


@pytest.mark.parametrize("rows", [[None], ["not a finding"], [{}], [{"title": " "}],
                                  [{"title": {"text": "not the supported title format"}}],
                                  [{"title": "Valid"}, False]])
def test_generic_malformed_rows_reject_whole_report(tmp_path, rows):
    path = tmp_path / "report.json"
    path.write_text(json.dumps({"findings": rows}), encoding="utf-8")
    with pytest.raises(ValueError):
        ReportImportAdapter().import_file(path)


@pytest.mark.parametrize("run", [None, {"tool": []}, {"tool": {"driver": []}},
                                  {"results": [None]}, {"results": [{}]}, {"results": "wrong"},
                                  {"results": [{"ruleId": 123}]}, {"results": [{"message": ["bad"]}]},
                                  {"tool": {"driver": {"rules": [{"properties": []}]}}},
                                  {"results": [{"ruleId": "rule", "locations": [None]}]},
                                  {"results": [{"ruleId": "rule", "locations": [{"physicalLocation": {"region": []}}]}]}])
def test_malformed_sarif_is_rejected_instead_of_skipped_or_crashing(tmp_path, run):
    path = tmp_path / "report.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": [run]}), encoding="utf-8")
    with pytest.raises(ValueError, match="SARIF"):
        ReportImportAdapter().import_file(path)


@pytest.mark.parametrize("score", [float("inf"), float("-inf"), float("nan"), "Infinity", "NaN", 10.1, -1, True, False, 10**1000])
def test_invalid_score_cannot_inflate_severity(score):
    assert _severity("info", score) == FindingSeverity.INFO
    assert _severity("high", score) == FindingSeverity.HIGH


@pytest.mark.parametrize("score,expected", [(9.8, "CRITICAL"), (10, "CRITICAL"), (7.5, "HIGH"), (4, "MEDIUM"), (1, "LOW"), (0.1, "LOW"), (0.9, "LOW"), (0, "INFO")])
def test_valid_scores_keep_supported_mapping(score, expected):
    assert _severity("info", score).value == expected


def test_explicit_zero_score_is_informational_even_with_error_level():
    assert _severity("error", 0) == FindingSeverity.INFO


def test_hydra_invalid_row_is_not_silently_dropped(tmp_path):
    path = tmp_path / "hydra.json"
    path.write_text(json.dumps({"generator": {"software": "hydra"}, "results": [None]}), encoding="utf-8")
    with pytest.raises(ValueError, match="no records were skipped"):
        ReportImportAdapter().import_file(path)


def test_valid_sarif_without_optional_location_or_tool_remains_supported(tmp_path):
    path = tmp_path / "valid.sarif"
    path.write_text(json.dumps({"version": "2.1.0", "runs": [{"results": [{"message": {"text": "Actual source message"}}]}]}), encoding="utf-8")
    scan, findings = ReportImportAdapter().import_file(path)
    assert scan.status == "COMPLETED" and len(findings) == 1
    assert findings[0].description == "Actual source message"
