"""PCAP Lab web server: serves the UI and a small JSON API."""
from __future__ import annotations

import json
import uuid
from pathlib import Path

import csv

from flask import Flask, abort, jsonify, request, send_file, send_from_directory

import decoders
from analysis import build_graph, conversation_filter, host_table
from hostnames import hostname_for
from pcap_reader import PcapError
from store import CaptureStore

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"
SAMPLES = ROOT / "samples"
UPLOADS = ROOT / "uploads"
EXPORTS = ROOT / "exports"
MAX_UPLOAD_MB = 50

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_MB * 1024 * 1024
store = CaptureStore()


# ---------- UI ----------

@app.get("/")
def index():
    return send_from_directory(FRONTEND, "index.html")


@app.get("/<path:asset>")
def frontend_asset(asset: str):
    return send_from_directory(FRONTEND, asset)


# ---------- API ----------

@app.get("/api/health")
def health():
    return jsonify(status="ok", decoders=decoders.registered())


@app.get("/api/samples")
def list_samples():
    catalog_file = SAMPLES / "catalog.json"
    catalog = json.loads(catalog_file.read_text(encoding="utf-8")) if catalog_file.exists() else {}
    samples = []
    for path in sorted(SAMPLES.glob("*.pcap")):
        meta = catalog.get(path.name, {})
        samples.append({"file": path.name, "title": meta.get("title", path.stem),
                        "description": meta.get("description", ""), "size": path.stat().st_size})
    return jsonify(samples=samples)


@app.post("/api/samples/<name>/open")
def open_sample(name: str):
    available = {p.name: p for p in SAMPLES.glob("*.pcap")}
    if name not in available:
        abort(404, description=f"No sample named {name}")
    return _open(available[name], name)


@app.post("/api/captures")
def upload_capture():
    file = request.files.get("file")
    if file is None or not file.filename:
        abort(400, description="No file was uploaded.")
    if not file.filename.lower().endswith((".pcap", ".cap")):
        abort(400, description="Upload a .pcap file.")
    UPLOADS.mkdir(exist_ok=True)
    path = UPLOADS / f"{uuid.uuid4().hex}.pcap"
    file.save(path)
    return _open(path, Path(file.filename).name)


def _open(path: Path, display_name: str):
    try:
        capture = store.open(path, display_name)
    except PcapError as exc:
        abort(400, description=str(exc))
    return jsonify(capture.info())


@app.get("/api/captures/<capture_id>")
def capture_info(capture_id: str):
    return jsonify(_capture(capture_id).info())


@app.get("/api/captures/<capture_id>/graph")
def capture_graph(capture_id: str):
    capture = _capture(capture_id)
    protocol = request.args.get("protocol") or None
    min_packets = request.args.get("min_packets", default=1, type=int)
    graph = build_graph(capture.packets, protocol=protocol, min_packets=min_packets)
    for node in graph["nodes"]:
        node["name"] = hostname_for(capture.packets, node["id"])
    return jsonify(graph)


@app.get("/api/captures/<capture_id>/hosts/<ip>")
def host_details(capture_id: str, ip: str):
    capture = _capture(capture_id)
    hosts = host_table(capture.packets)
    if ip not in hosts:
        abort(404, description=f"{ip} is not in this capture")
    return jsonify({**hosts[ip], "name": hostname_for(capture.packets, ip)})


@app.get("/api/captures/<capture_id>/export")
def export_conversations(capture_id: str):
    """Write the conversation list as CSV and download it."""
    capture = _capture(capture_id)
    filename = request.args.get("filename", "conversations.csv")
    graph = build_graph(capture.packets)
    EXPORTS.mkdir(exist_ok=True)
    path = EXPORTS / filename
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["host_a", "host_b", "packets", "bytes", "protocols", "services"])
        for e in graph["edges"]:
            writer.writerow([e["source"], e["target"], e["packets"], e["bytes"],
                             " ".join(e["protocols"]), " ".join(e["services"])])
    return send_file(path, as_attachment=True, download_name=Path(filename).name)


@app.get("/api/captures/<capture_id>/packets")
def list_packets(capture_id: str):
    capture = _capture(capture_id)
    port = request.args.get("port", type=int)
    selected = conversation_filter(capture.packets, ip=request.args.get("ip") or None,
                                   peer=request.args.get("peer") or None,
                                   protocol=request.args.get("protocol") or None, port=port)
    offset = max(request.args.get("offset", default=0, type=int), 0)
    limit = min(max(request.args.get("limit", default=200, type=int), 1), 1000)
    start = capture.summary["start"] or 0
    rows = [{
        "index": p.index,
        "time": round(p.timestamp - start, 6),
        "src": p.src_ip, "dst": p.dst_ip,
        "protocol": p.protocol,
        "service": p.service,
        "length": p.wire_length,
        "info": p.info,
    } for p in selected[offset:offset + limit]]
    return jsonify(total=len(selected), offset=offset, packets=rows)


@app.get("/api/captures/<capture_id>/packets/<int:index>")
def packet_details(capture_id: str, index: int):
    capture = _capture(capture_id)
    if not 0 <= index < len(capture.packets):
        abort(404, description="No such packet")
    p = capture.packets[index]
    layers = [layer.to_dict() for layer in p.layers]
    app_layer, decode_error = decoders.decode_application(p)
    if app_layer:
        layers.append(app_layer.to_dict())
    elif p.payload:
        layers.append({"name": "Data", "summary": f"{len(p.payload)} bytes",
                       "offset": p.payload_offset, "length": len(p.payload), "fields": []})
    return jsonify(index=p.index, time=round(p.timestamp - (capture.summary["start"] or 0), 6),
                   length=p.wire_length, protocol=p.protocol, layers=layers,
                   decode_error=decode_error, hex=p.data.hex())


def _capture(capture_id: str):
    capture = store.get(capture_id)
    if capture is None:
        abort(404, description="Capture not found. Open it again.")
    return capture


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(413)
def json_error(error):
    message = getattr(error, "description", str(error))
    if error.code == 413:
        message = f"The file is larger than {MAX_UPLOAD_MB} MB."
    return jsonify(error=message), error.code
