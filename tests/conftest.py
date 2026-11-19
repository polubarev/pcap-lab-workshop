import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))
sys.path.insert(0, str(ROOT / "tests"))

from pcap_builder import pcap_bytes, small_capture  # noqa: E402


@pytest.fixture
def small_pcap(tmp_path) -> Path:
    path = tmp_path / "small.pcap"
    path.write_bytes(pcap_bytes(small_capture()))
    return path
