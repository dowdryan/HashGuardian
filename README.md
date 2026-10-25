# File Integrity Monitor (FIM)

A local prototype that tracks file integrity using SHA-256 hashes and stores events in SQLite. It includes a conservative rule-based risk explanation and an integration seam for an Adaption Labs-hosted model.

## Requirements

- Python 3.10+
- Permission to read the directories you intend to monitor

## Run locally

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows PowerShell
# .venv\Scripts\Activate.ps1

pip install -r requirements.txt
streamlit run app.py
```

Open the local URL printed by Streamlit.

## Safe first run

1. Start with a test directory containing non-sensitive sample files.
2. Create a baseline only when you trust the current contents.
3. Change or add a test file.
4. Click **Scan for changes** and review the events.
5. Export the event log if needed.

## Adaption Labs AI

Official docs:
- https://docs.adaptionlabs.ai/
- https://docs.adaptionlabs.ai/api/
- https://docs.adaptionlabs.ai/introduction/create-api-keys/

The documented platform includes Adaptive Data and AutoScientist APIs for dataset optimization and model training. Do not treat those endpoints as a generic live inference API. To enable AI classification of live events, deploy a model with an available inference contract, then implement `ai_adapter.py` against that documented contract. Keep keys server-side.

For a task-specific model, build a curated dataset of sanitized file-event metadata (event type, file category, baseline status, timestamp features, and verified analyst label). Avoid collecting file contents, credentials, or unnecessary personal data. Adaption Adaptive Data / AutoScientist can be evaluated for dataset preparation and model training, subject to the account's supported workflows.

## Security limitations

- This is a prototype, not an enterprise-grade EDR or compliance product.
- SHA-256 detects content changes relative to a trusted baseline; it does not prove who made a change.
- A user with sufficient privileges may tamper with the database and baseline. Production deployments should store baselines and audit logs in a separately protected location, ideally append-only or remote.
- The scan is periodic/on-demand, not a kernel-level real-time watcher.
- Symlinks are skipped; files larger than the configured limit and common dependency directories are skipped.
- Baseline refresh overwrites trust data. Restrict that operation and record approvals in production.
- Test carefully before monitoring operating-system directories.
