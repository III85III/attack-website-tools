"""
Unit tests for PCAP / TShark adapter.
"""
import struct
import tempfile
from pathlib import Path

from src.adapters.pcap_adapter import PcapAdapter


def test_pcap_detection():
    adapter = PcapAdapter()
    health = adapter.detect()
    assert health.name == "TShark / PCAP"
    # Even if TShark is not installed, clear honest message is given
    assert isinstance(health.installed, bool)


def test_native_pcap_parser():
    adapter = PcapAdapter()

    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp_path = tmp.name

        # Write standard libpcap header (magic 0xA1B2C3D4, v2.4, snaplen 65535, linktype 1 Ethernet)
        hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        tmp.write(hdr)

        # Write one dummy packet header: ts_sec, ts_usec, incl_len, orig_len
        pkt_data = b"\x00" * 54  # Dummy Ethernet + IP + TCP header
        pkt_hdr = struct.pack("<IIII", 1700000000, 0, len(pkt_data), len(pkt_data))
        tmp.write(pkt_hdr)
        tmp.write(pkt_data)

    try:
        res = adapter.analyze_pcap_file(tmp_path)
        assert res.get("total_packets") == 1
        assert "file_name" in res
    finally:
        Path(tmp_path).unlink(missing_ok=True)
