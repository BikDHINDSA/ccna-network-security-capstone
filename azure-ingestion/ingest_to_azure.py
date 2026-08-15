import os
import json
from dotenv import load_dotenv
from azure.identity import InteractiveBrowserCredential
from azure.monitor.ingestion import LogsIngestionClient

load_dotenv()

INGESTION_ENDPOINT = os.getenv("INGESTION_ENDPOINT")
DCR_ID = os.getenv("DCR_ID")
STREAM_NAME = os.getenv("STREAM_NAME")

credential = InteractiveBrowserCredential(tenant_id=os.getenv("TENANT_ID"))
client = LogsIngestionClient(endpoint=INGESTION_ENDPOINT, credential=credential)

device_files = [
    "../detection/parsed_output/L3-Core_Events.json",
    "../detection/parsed_output/Access-SW1_Events.json",
    "../detection/parsed_output/Access-SW2_Events.json",
]

for path in device_files:
    with open(path) as f:
        logs = json.load(f)
    client.upload(rule_id=DCR_ID, stream_name=STREAM_NAME, logs=logs)
    print(f"Uploaded {len(logs)} events from {path}")