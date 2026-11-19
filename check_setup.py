"""Check that this machine is ready for the workshop: python check_setup.py"""
from __future__ import annotations

import importlib
import shutil
import socket
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
WINDOWS = sys.platform == "win32"
OK, FAIL = "[ OK ]", "[FAIL]"
ACTIVATE = r".venv\Scripts\Activate.ps1" if WINDOWS else "source .venv/bin/activate"
INSTALL_PYTHON = ("Install Python 3.11 or newer from python.org and tick 'Add python.exe to PATH'." if WINDOWS
                  else "Install Python 3.11 or newer from python.org (or: brew install python@3.12).")
INSTALL_GIT = ("Install Git for Windows from git-scm.com." if WINDOWS
               else "Install Git: run xcode-select --install (macOS) or use your package manager.")
problems = 0


def report(ok: bool, message: str, fix: str = "") -> None:
    global problems
    print(f"{OK if ok else FAIL} {message}")
    if not ok:
        problems += 1
        if fix:
            print(f"       -> {fix}")


def main() -> int:
    version = sys.version_info
    report(version >= (3, 11), f"Python {version.major}.{version.minor}.{version.micro}",
           INSTALL_PYTHON)

    in_venv = sys.prefix != sys.base_prefix
    report(in_venv, "Running inside a virtual environment",
           f"Activate it first: {ACTIVATE}")

    for module in ("flask", "networkx", "pytest"):
        try:
            importlib.import_module(module)
            report(True, f"Package '{module}' is installed")
        except ImportError:
            report(False, f"Package '{module}' is missing", "Run: pip install -r requirements.txt")

    git = shutil.which("git")
    report(git is not None, "Git is installed", INSTALL_GIT)
    if git:
        inside = subprocess.run([git, "rev-parse", "--is-inside-work-tree"], cwd=ROOT,
                                capture_output=True, text=True).stdout.strip() == "true"
        report(inside, "This folder is a Git clone", "Clone the repository with git clone instead of downloading a ZIP.")

    sample = ROOT / "samples" / "office-network.pcap"
    try:
        sys.path.insert(0, str(ROOT / "backend"))
        from pcap_reader import read_pcap
        packets = read_pcap(sample)
        report(len(packets) > 1000, f"Sample capture opens ({len(packets)} packets)")
    except Exception as exc:  # report any failure in plain words
        report(False, f"Sample capture does not open: {exc}", "Run git status; the samples folder may be incomplete.")

    with socket.socket() as s:
        free = s.connect_ex(("127.0.0.1", 8050)) != 0
    report(free, "Port 8050 is free", "Something else uses port 8050. Stop it, or run: python run.py --port 8060")

    print()
    if problems:
        print(f"{problems} problem(s) found. Fix them, then run this check again.")
        return 1
    print("All set. Start the app with: python run.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
