import os
import time
from adaption import Adaption

api_key = os.environ.get("ADAPTION_API_KEY")

if not api_key:
    raise RuntimeError(
        "ADAPTION_API_KEY is not set. "
        "Configure your API key before running this script."
    )

client = Adaption(api_key=api_key)

# Step 1: Upload file
dataset = client.datasets.upload_file(
    "fim_event_classification.csv",
    name="fim_event_classification",
)

# Step 2: Wait for ingestion to finish (row_count populated)
while True:
    status = client.datasets.get_status(dataset.dataset_id)
    if status.status == "failed":
        err = status.error_data
        msg = (err and err.message) or "unknown error"
        raise RuntimeError(f"Ingestion failed: {msg}")
    if status.row_count is not None:
        break
    time.sleep(5)

# Step 3: Adapt dataset
job = client.datasets.adapt(
    dataset.dataset_id,
    training_type="instruction_dataset",
)
print(f"Launched — estimated time: {job.estimated_minutes:.0f} minutes")

# Step 4: Poll until complete
while True:
    status = client.datasets.get_status(dataset.dataset_id)
    if status.status == "succeeded":
        break
    if status.status == "failed":
        err = status.error_data
        msg = (err and err.message) or "unknown error"
        raise RuntimeError(f"Adaptation failed: {msg}")
    time.sleep(10)

# Step 5: Review results
ds = client.datasets.get(dataset.dataset_id)
if ds.evaluation_summary:
    print(f"Quality: {ds.evaluation_summary.grade_before} → {ds.evaluation_summary.grade_after}")
    print(f"Improvement: {ds.evaluation_summary.improvement_percent:.0f}%")

# Step 6: Download
client.datasets.download(dataset.dataset_id)