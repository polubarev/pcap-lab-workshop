# PCAP Lab

PCAP Lab is a small web app for exploring network captures. Open a `.pcap` file and see:

- **Network graph:** every host as a node and every conversation as a line, sized by traffic. Internal and external hosts and hubs are marked.
- **Inspector:** protocol breakdown, top talkers, top ports, and details of any host or conversation you click.
- **Traffic over time:** packets per time slice across the capture.
- **Packets:** a filterable packet list. Select a packet to see its layers (Ethernet, IPv4, TCP/UDP/ICMP/ARP and application protocols such as DNS) and its raw bytes. Hover a field to highlight its bytes.

It is the base application for the **IBM Bob hands-on workshop**. Workshop tasks are on the [wiki](../../wiki).

## Set up (Windows)

You need **Python 3.11 or newer** and **Git**. Check in PowerShell:

```powershell
python --version
git --version
```

Clone the repository and install the dependencies:

```powershell
git clone https://github.com/polubarev/pcap-lab-workshop.git
cd pcap-lab-workshop
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

If PowerShell refuses to run `Activate.ps1`, allow scripts for this window only and try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.venv\Scripts\Activate.ps1
```

On macOS or Linux, use `python3 -m venv .venv` and `source .venv/bin/activate` instead.

Check that everything is ready:

```powershell
python check_setup.py
```

## Run

```powershell
python run.py
```

The app opens at <http://127.0.0.1:8050>. Pick the **Office network** sample or drop your own `.pcap` file. Press `Ctrl+C` in the terminal to stop it.

Options: `--port 8060` to use another port, `--no-browser` to skip opening a browser tab, `--debug` to reload on code changes.

## Test

```powershell
python -m pytest
```

## Project layout

| Path | What it holds |
|---|---|
| `run.py` | Starts the web server |
| `backend/app.py` | HTTP API and static file serving (Flask) |
| `backend/pcap_reader.py` | Reads pcap files and decodes Ethernet, ARP, IPv4, TCP, UDP and ICMP |
| `backend/analysis.py` | Summary statistics, top talkers and ports, timeline, network graph |
| `backend/decoders/` | Application-protocol decoders (plugins), for example DNS |
| `backend/store.py` | Captures opened in this session (in memory) |
| `frontend/` | The web UI: plain HTML, CSS and JavaScript modules, no build step |
| `samples/` | Sample captures shown on the start screen |
| `tests/` | Tests, with helpers that build small captures in memory |

See [architecture](docs/architecture.md) for how a capture becomes the graph and the packet view.

## Working with IBM Bob

Open the repository folder in Bob IDE (**File → Open Folder…**). Project rules for Bob are in `.bob/rules/`.

## Limits

- Classic pcap files only. Save pcapng captures from Wireshark as *Wireshark/tcpdump - pcap*.
- Ethernet captures only. IPv6 is not decoded.
- Uploads up to 50 MB. Captures are kept in memory until the server stops.

The sample capture is synthetic. It contains no real traffic.
