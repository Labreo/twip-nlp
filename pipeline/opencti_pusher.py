import os
import glob
from dotenv import load_dotenv
import json  # <-- Added this import
from pycti import OpenCTIApiClient

# --- Configuration ---
# Use the exact URL and Token from your OpenCTI .env setup

opencti_url = os.getenv("OPENCTI_URL")
  # Replace with the UUID you generated
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
                # <-- FIX: Parse the JSON string into a Python dictionary
                stix_data = json.load(f) 
                
            # Upload the parsed dictionary to OpenCTI
            api_client.stix2.import_bundle(stix_data)
            print(f"  -> Success: {filename}")
            
        except Exception as e:
            print(f"  -> Error pushing {filename}: {e}")

if __name__ == "__main__":
    push_stix_bundles()