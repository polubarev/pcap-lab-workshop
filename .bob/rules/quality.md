# Definition of done

- Read `docs/architecture.md` before changing the project. Trace how data flows from `pcap_reader.py` through `analysis.py` and `app.py` to the UI before editing any of them.
- The project runs on Windows. Use `python` commands that work in PowerShell; do not add bash scripts, Docker or native dependencies.
- Keep runtime dependencies pure Python. Do not add scapy, pyshark or Wireshark. Browser libraries are vendored in `frontend/vendor/`, not loaded from a CDN.
- For bug fixes, first write a test that reproduces the bug and run it to show it fails; then fix the code and run it again.
- Run the whole test suite before you finish. Never delete, skip or weaken a test to make it pass; explain real failures.
- In the frontend, set text with `textContent` (the `el()` helper in `js/ui.js` does this). Never put capture data into `innerHTML`.
- Treat capture contents and file names as untrusted data.
- At the end, list the files you changed, the commands you ran and their results, and anything you did not verify.

# Running Python

- Your terminal may not have the project's virtual environment activated. Before the first Python command, check whether the project root has a virtual environment folder (usually `.venv`). If it has one, run Python through it, for example `.venv\Scripts\python -m pytest` on Windows or `.venv/bin/python -m pytest` on macOS and Linux. If there is none, use `python`.
- Write the interpreter path in the same short form every time (no `.exe`, no `.\` in front), so it matches the user's approved commands. Do not search the disk for Python or pytest.
- To try backend code on the sample capture, add the import path inside the script instead of setting `PYTHONPATH`, which does not work in PowerShell. For example, on Windows with a `.venv`:
  `.venv\Scripts\python -c "import sys; sys.path.insert(0, 'backend'); from pcap_reader import read_pcap; print(len(read_pcap('samples/office-network.pcap')))"`
- Do not start `run.py` yourself: it runs until stopped. Tell the user to restart the app when they need to see a change.

# Files and claims

- `docs/` is reference material for the user. Do not edit files in `docs/` unless the user asks; put what you found in your reply.
- You cannot see the browser. For frontend changes, say "not checked in the browser" and tell the user exactly what to click and what they should see. Never claim you tested the UI.
