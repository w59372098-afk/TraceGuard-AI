# TraceGuard AI

**Evidence-first security log investigation — a local learning proof of concept.**

TraceGuard AI parses plain-text application/security logs, highlights a few suspicious patterns with transparent rules, displays the matched evidence, and exports Markdown and CSV reports.

## Features

- Upload `.log` or `.txt` files, or load the simulated sample dataset.
- Parse timestamps, severity-like labels, source IPs, and messages.
- Flag repeated authentication failures, common web-probing indicators, and selected command-like strings.
- Inspect the exact log lines that caused each finding.
- Export an investigation report (`.md`) and findings (`.csv`).
- Runs locally; no API key required.

## Run on Windows

1. Install Python 3.10+ and Git if needed.
2. Extract this folder and open it in VS Code.
3. Open Terminal → New Terminal and run:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
streamlit run app.py
```

If PowerShell blocks activation, use Command Prompt and run:

```bat
.venv\Scripts\activate.bat
```

Then run `pip install -r requirements.txt` and `streamlit run app.py`.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Input format

The parser works on line-oriented plain text. It looks for timestamps in `YYYY-MM-DD HH:MM:SS` format, IPv4 addresses, and common severity labels. Other lines are retained as events with unknown fields.

## Limitations and safe use

- This is a small proof of concept, not a production security product or a substitute for a SIEM.
- Rules are heuristic and can produce false positives and false negatives.
- A flagged pattern is not proof of compromise; a clean result is not proof that a system is safe.
- Use only logs you are authorized to inspect. Sample IP addresses are reserved documentation ranges.
- Uploaded content is processed in the local app process; do not upload sensitive logs to a shared/public deployment.
- No AI model is called in this version; explanations are template-based and evidence-linked.

## Project status

Learning project. It has not been submitted to, reviewed by, or approved for any hackathon. For any competition, independently verify eligibility and follow the event's required workflow and submission rules.
