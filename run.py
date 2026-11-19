"""Start PCAP Lab: python run.py  (add --no-browser to skip opening the browser)."""
from __future__ import annotations

import argparse
import sys
import threading
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "backend"))

from app import app  # noqa: E402


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the PCAP Lab web app.")
    parser.add_argument("--port", type=int, default=8050)
    parser.add_argument("--no-browser", action="store_true", help="do not open a browser tab")
    parser.add_argument("--debug", action="store_true", help="reload on code changes")
    args = parser.parse_args()

    url = f"http://127.0.0.1:{args.port}"
    print(f"PCAP Lab is running at {url}  (press Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=args.port, debug=args.debug, use_reloader=args.debug)


if __name__ == "__main__":
    main()
