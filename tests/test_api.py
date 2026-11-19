import io

import pytest

from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    return app.test_client()


@pytest.fixture
def capture_id(client, small_pcap):
    response = client.post("/api/captures", data={"file": (io.BytesIO(small_pcap.read_bytes()), "small.pcap")},
                           content_type="multipart/form-data")
    assert response.status_code == 200
    return response.get_json()["id"]


def test_index_serves_the_ui(client):
    response = client.get("/")
    assert response.status_code == 200
    assert b"PCAP Lab" in response.data


def test_samples_are_listed_and_open(client):
    samples = client.get("/api/samples").get_json()["samples"]
    assert samples, "the samples folder should contain at least one capture"
    opened = client.post(f"/api/samples/{samples[0]['file']}/open").get_json()
    assert opened["summary"]["packets"] > 0


def test_unknown_sample_is_404(client):
    assert client.post("/api/samples/missing.pcap/open").status_code == 404
    # A path in the name never reaches the sample endpoint, so nothing outside samples/ can be opened.
    assert client.post("/api/samples/..%2Fbackend%2Fapp.py/open").status_code in (404, 405)


def test_upload_rejects_non_pcap(client):
    response = client.post("/api/captures", data={"file": (io.BytesIO(b"hello"), "notes.txt")},
                           content_type="multipart/form-data")
    assert response.status_code == 400
    assert "pcap" in response.get_json()["error"]


def test_graph(client, capture_id):
    graph = client.get(f"/api/captures/{capture_id}/graph?protocol=TCP").get_json()
    assert len(graph["nodes"]) == 3


def test_packet_list_and_filters(client, capture_id):
    page = client.get(f"/api/captures/{capture_id}/packets?port=53").get_json()
    assert page["total"] == 1
    assert page["packets"][0]["service"] == "DNS"
    tcp = client.get(f"/api/captures/{capture_id}/packets?protocol=TCP&ip=10.0.0.6").get_json()
    assert tcp["total"] == 1


def test_packet_details(client, capture_id):
    details = client.get(f"/api/captures/{capture_id}/packets/3").get_json()
    assert [layer["name"] for layer in details["layers"]] == ["Ethernet II", "IPv4", "UDP", "DNS"]
    assert len(details["hex"]) == details["length"] * 2


def test_host_details(client, capture_id):
    host = client.get(f"/api/captures/{capture_id}/hosts/10.0.0.5").get_json()
    assert host["packets_sent"] == 5   # 2 TCP, DNS, ICMP, ARP
    assert host["internal"] is True


def test_unknown_capture_is_404(client):
    assert client.get("/api/captures/nope/graph").status_code == 404
