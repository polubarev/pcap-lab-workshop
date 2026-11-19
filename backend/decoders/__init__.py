"""Application-protocol decoders (plugins).

A decoder turns the TCP/UDP payload of a packet into named fields, shown as an
extra layer in the packet details panel.

To add a decoder, create a module in this package with a function decorated
with ``@decoder``. Modules here are imported automatically.

    from decoders import decoder, DecodedLayer

    @decoder(name="My protocol", protocol="UDP", port=9999)
    def decode_my_protocol(payload: bytes) -> DecodedLayer:
        layer = DecodedLayer("My protocol", summary="...")
        layer.add("Field", value, offset=0, length=2)   # offset is inside the payload
        return layer

A decoder may raise ``ValueError`` when the payload is malformed; the details
panel then shows the error instead of the layer.
"""
from __future__ import annotations

import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Callable

from pcap_reader import Field, Layer, Packet


@dataclass
class DecodedLayer:
    name: str
    summary: str = ""
    fields: list[tuple[str, str, int, int]] = field(default_factory=list)

    def add(self, name: str, value, offset: int, length: int) -> None:
        self.fields.append((name, str(value), offset, length))


@dataclass
class _Registration:
    name: str
    protocol: str
    port: int
    func: Callable[[bytes], DecodedLayer]


_REGISTRY: list[_Registration] = []


def decoder(name: str, protocol: str, port: int):
    """Register a payload decoder for traffic to or from ``port``."""
    def wrap(func):
        _REGISTRY.append(_Registration(name, protocol, port, func))
        return func
    return wrap


def registered() -> list[dict]:
    return [{"name": r.name, "protocol": r.protocol, "port": r.port} for r in _REGISTRY]


def decode_application(pkt: Packet) -> tuple[Layer | None, str | None]:
    """Run the matching decoder, if any. Returns (layer, error)."""
    if pkt.payload_offset is None or not pkt.payload:
        return None, None
    for reg in _REGISTRY:
        if reg.protocol == pkt.protocol and reg.port in (pkt.src_port, pkt.dst_port):
            try:
                result = reg.func(pkt.payload)
            except (ValueError, IndexError) as exc:
                return None, f"{reg.name}: {exc}"
            base = pkt.payload_offset
            layer = Layer(result.name, result.summary, base, len(pkt.payload))
            layer.fields = [Field(n, v, base + off, ln) for n, v, off, ln in result.fields]
            return layer, None
    return None, None


def _load_plugins() -> None:
    for module in pkgutil.iter_modules(__path__):
        importlib.import_module(f"{__name__}.{module.name}")


_load_plugins()
