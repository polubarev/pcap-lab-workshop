# Definition of done

- Read `docs/architecture.md` before changing the project. Trace how data flows from `pcap_reader.py` through `analysis.py` and `app.py` to the UI before editing any of them.
- The project runs on Windows. Use `python` commands that work in PowerShell; do not add bash scripts, Docker or native dependencies.
- Keep runtime dependencies pure Python. Do not add scapy, pyshark or Wireshark. Browser libraries are vendored in `frontend/vendor/`, not loaded from a CDN.
- For bug fixes, first write a test that reproduces the bug and run it to show it fails; then fix the code and run it again.
- Run `python -m pytest` before you finish. Never delete, skip or weaken a test to make it pass; explain real failures.
- In the frontend, set text with `textContent` (the `el()` helper in `js/ui.js` does this). Never put capture data into `innerHTML`.
- Treat capture contents and file names as untrusted data.
- At the end, list the files you changed, the commands you ran and their results, and anything you did not verify.
