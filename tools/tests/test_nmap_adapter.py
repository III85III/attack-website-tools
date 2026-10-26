"""
Unit tests for Nmap adapter: target validation, XML parsing, and error handling.
"""
import pytest

from src.adapters.nmap_adapter import NmapAdapter
from src.core.models import FindingSeverity, FindingStatus


SAMPLE_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -p 135,445 127.0.0.1" start="1700000000" version="7.99">
<host starttime="1700000000" endtime="1700000001">
<status state="up" reason="localhost-response"/>
<address addr="127.0.0.1" addrtype="ipv4"/>
<hostnames><hostname name="localhost" type="PTR"/></hostnames>
<ports>
<port protocol="tcp" portid="135">
<state state="open" reason="syn-ack"/>
<service name="msrpc" product="Microsoft Windows RPC" version="10.0"/>
</port>
<port protocol="tcp" portid="445">
<state state="open" reason="syn-ack"/>
<service name="microsoft-ds" product="Windows SMB"/>
</port>
<port protocol="tcp" portid="80">
<state state="closed" reason="conn-refused"/>
</port>
</ports>
</host>
</nmaprun>
"""


def test_target_validation():
    adapter = NmapAdapter()

    # Validation checks target syntax only; the UI requires explicit scope approval
    # before any network scan is launched.
    assert adapter.validate_target("127.0.0.1")[0] is True
    assert adapter.validate_target("localhost")[0] is True
    assert adapter.validate_target("scanme.nmap.org")[0] is True
    assert adapter.validate_target("192.168.1.1/24")[0] is False
    assert adapter.validate_target("192.168.1.1")[0] is True

    # Injection attempts / invalid targets
    assert adapter.validate_target("127.0.0.1; rm -rf /")[0] is False
    assert adapter.validate_target("127.0.0.1 && dir")[0] is False
    assert adapter.validate_target("127.0.0.1 | whoami")[0] is False
    assert adapter.validate_target("")[0] is False
    assert adapter.validate_target("   ")[0] is False


def test_xml_output_parsing():
    adapter = NmapAdapter()
    findings, err = adapter.parse_xml_output(SAMPLE_NMAP_XML, "scan-123", "127.0.0.1")

    assert err is None
    # Only open ports (135 and 445) should be reported, port 80 is closed
    assert len(findings) == 2

    f_135 = next(f for f in findings if "135" in f.target)
    assert f_135.title == "Open Port 135/TCP (msrpc) on 127.0.0.1"
    assert f_135.confidence.value == "CONFIRMED"
    assert f_135.status == FindingStatus.OBSERVED
    assert f_135.affected_component == "Microsoft Windows RPC 10.0"

    f_445 = next(f for f in findings if "445" in f.target)
    assert f_445.severity == FindingSeverity.MEDIUM
    assert f_445.affected_component == "Windows SMB"


def test_malformed_xml_handling():
    adapter = NmapAdapter()
    findings, err = adapter.parse_xml_output("<broken><xml>", "scan-999", "127.0.0.1")
    assert findings == []
    assert err is not None
    assert "malformed" in err.lower() or "syntax" in err.lower()


def test_missing_nmap_executable():
    adapter = NmapAdapter(executable_path="C:\\nonexistent\\nmap.exe")
    health = adapter.detect()
    assert health.installed is False
    assert "not found" in health.status_message.lower()


@pytest.mark.parametrize("ports", ["80", "80,443", "1-1024", "8000-8100,8443"])
def test_port_spec_accepts_numeric_lists_and_ranges(ports):
    assert NmapAdapter.validate_port_spec(ports)[0] is True


@pytest.mark.parametrize(
    "ports",
    ["0", "65536", "100-1", "80;--script=default", "--script=http-title", "80,", "1-2-3"],
)
def test_port_spec_rejects_options_and_invalid_ranges(ports):
    assert NmapAdapter.validate_port_spec(ports)[0] is False
