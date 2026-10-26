"""
Unit tests for CVE & CISA KEV intelligence correlation engine.
"""
from src.core.cve_intel import CVEIntelligenceEngine
from src.core.models import FindingSeverity, FindingStatus


def test_cve_correlation_matches_known_component():
    engine = CVEIntelligenceEngine()

    # Correlate OpenSSH
    findings = engine.correlate_component("OpenSSH", "9.2", "127.0.0.1:22")
    assert len(findings) >= 1
    assert any("CVE-2024-6387" in f.title or "CVE-2023-38606" in f.title for f in findings)
    assert findings[0].status == FindingStatus.POTENTIAL
    assert findings[0].severity == FindingSeverity.HIGH


def test_cve_correlation_does_not_invent_findings():
    engine = CVEIntelligenceEngine()

    # Query a benign, non-vulnerable or unknown component
    findings = engine.correlate_component("CustomSafeInternalTool", "1.0", "127.0.0.1:9000")
    assert len(findings) == 0
