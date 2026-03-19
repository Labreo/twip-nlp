import os
import glob
import shutil  # <-- Added for safe file moving
import json
from dotenv import load_dotenv
from pycti import OpenCTIApiClient

# --- Configuration ---
# FIX: You have to actually call load_dotenv() to read the .env file!
load_dotenv()

opencti_url = os.getenv("OPENCTI_URL")
opencti_token = os.getenv("OPENCTI_TOKEN")

def push_stix_bundles():
    print("Connecting to OpenCTI...")
    try:
        api_client = OpenCTIApiClient(opencti_url, opencti_token)
        print("Successfully connected to OpenCTI instance.")
    except Exception as e:
        print(f"Connection failed: {e}")
        return

    # 1. Get the directory where this script lives
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    
    # 2. Go up one level (..) and into the 'output' folder
    output_dir = os.path.abspath(os.path.join(current_script_dir, '..', 'output'))
    
    # --- NEW: Create the 'ingested' directory if it doesn't exist ---
    ingested_dir = os.path.join(output_dir, 'ingested')
    os.makedirs(ingested_dir, exist_ok=True)

    bundle_files = glob.glob(os.path.join(output_dir, 'stix_bundle_*.json'))

    if not bundle_files:
        print(f"No STIX bundles found in the directory: {output_dir}")
        return

    print(f"Found {len(bundle_files)} bundles. Beginning ingestion...")
    
    for file_path in bundle_files:
        filename = os.path.basename(file_path)
        print(f"Pushing {filename}...")
        try:
            with open(file_path, 'r') as f:
                stix_data = json.load(f) 
                
            # Upload the parsed dictionary to OpenCTI
            api_client.stix2.import_bundle(stix_data)
            print(f"  -> Success: {filename}")
            
            # --- NEW: Move the file to the 'ingested' folder ---
            shutil.move(file_path, os.path.join(ingested_dir, filename))
            print(f"  -> Moved {filename} to archive.")
            
        except Exception as e:
            print(f"  -> Error pushing {filename}: {e}")

if __name__ == "__main__":
    push_stix_bundles()