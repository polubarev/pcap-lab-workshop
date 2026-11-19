"""Opened captures, kept in memory for the lifetime of the server."""
from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from analysis import summarize
from pcap_reader import Packet, read_pcap


@dataclass
class Capture:
    id: str
    name: str
    size: int
    packets: list[Packet]
    summary: dict

    def info(self) -> dict:
        return {"id": self.id, "name": self.name, "size": self.size, "summary": self.summary}


class CaptureStore:
    def __init__(self) -> None:
        self._captures: dict[str, Capture] = {}
        self._lock = threading.Lock()

    def open(self, path: Path, display_name: str) -> Capture:
        packets = read_pcap(path)
        capture = Capture(id=uuid.uuid4().hex[:12], name=display_name, size=path.stat().st_size,
                          packets=packets, summary=summarize(packets))
        with self._lock:
            self._captures[capture.id] = capture
        return capture

    def get(self, capture_id: str) -> Capture | None:
        with self._lock:
            return self._captures.get(capture_id)
