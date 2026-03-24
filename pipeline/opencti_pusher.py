import os
import glob
import shutil
import json
import time
from dotenv import load_dotenv
from pycti import OpenCTIApiClient

load_dotenv()

opencti_url = os.getenv("OPENCTI_URL")
opencti_token = os.getenv("OPENCTI_TOKEN")

if not opencti_url or not opencti_token:
    raise ValueError("OPENCTI_URL and OPENCTI_TOKEN must be set in .env")

def push_stix_bundles(api_client, output_dir, ingested_dir):
    bundle_files = glob.glob(os.path.join(output_dir, 'stix_bundle_*.json'))

    if not bundle_files:
        # Silently return if empty so we don't spam the console
        return

    print(f"\n[+] Found {len(bundle_files)} new bundles. Beginning ingestion...")
    
    for file_path in bundle_files:
        filename = os.path.basename(file_path)
        print(f"  -> Pushing {filename}...")
        try:
            with open(file_path, 'r') as f:
                stix_data = json.load(f) 
                
            api_client.stix2.import_bundle(stix_data)
            shutil.move(file_path, os.path.join(ingested_dir, filename))
            print(f"  -> Success: Moved to archive.")
            
        except Exception as e:
            print(f"  -> Error pushing {filename}: {e}")

if __name__ == "__main__":
    print("Connecting to OpenCTI...")
    try:
        client = OpenCTIApiClient(opencti_url, opencti_token)
        print("Successfully connected to OpenCTI instance.")
    except Exception as e:
        print(f"Connection failed: {e}")
        exit(1)

    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    target_output_dir = os.path.abspath(os.path.join(current_script_dir, '..', 'output'))
    target_ingested_dir = os.path.join(target_output_dir, 'ingested')
    os.makedirs(target_ingested_dir, exist_ok=True)

    print("Watching for new STIX bundles... (Ctrl+C to stop)")
    while True:
        push_stix_bundles(client, target_output_dir, target_ingested_dir)
        time.sleep(10)