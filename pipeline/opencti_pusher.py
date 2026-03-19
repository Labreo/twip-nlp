import os
import glob
from pycti import OpenCTIApiClient

# --- Configuration ---
# Use the exact URL and Token from your OpenCTI .env setup
OPENCTI_URL = "http://localhost:8080"
OPENCTI_TOKEN = "YOUR_UUID_TOKEN_HERE"  # Replace with the UUID you generated

def push_stix_bundles():
    print("Connecting to OpenCTI...")
    try:
        api_client = OpenCTIApiClient(OPENCTI_URL, OPENCTI_TOKEN)
        print("Successfully connected to OpenCTI instance.")
    except Exception as e:
        print(f"Connection failed: {e}")
        return

    # Find all STIX bundles in the output directory
    output_dir = os.path.join(os.path.dirname(__dirname__), 'output')
    bundle_files = glob.glob(os.path.join(output_dir, 'stix_bundle_*.json'))

    if not bundle_files:
        print("No STIX bundles found in the /output directory.")
        return

    print(f"Found {len(bundle_files)} bundles. Beginning ingestion...")
    
    for file_path in bundle_files:
        filename = os.path.basename(file_path)
        print(f"Pushing {filename}...")
        try:
            with open(file_path, 'r') as f:
                stix_data = f.read()
                
            # Upload the bundle to OpenCTI
            api_client.stix2.import_bundle(stix_data)
            print(f"  -> Success: {filename}")
            
            # Optional: Move the file to an 'ingested' folder so it doesn't get pushed twice
            # os.rename(file_path, os.path.join(output_dir, 'ingested', filename))
            
        except Exception as e:
            print(f"  -> Error pushing {filename}: {e}")

if __name__ == "__main__":
    push_stix_bundles()