import json
import requests
import time
import os

# Configuration
ENDPOINT = "http://localhost:5001/ingest"
FILE_PATH = os.path.join("input", "all_posts.json")

def push_mock_data():
    if not os.path.exists(FILE_PATH):
        print(f"[!] Error: Could not find '{FILE_PATH}'. Ensure it is in the /input folder.")
        return

    # Load the JSON file
    with open(FILE_PATH, 'r') as f:
        try:
            posts = json.load(f)
        except json.JSONDecodeError:
            print("[!] Error: all_posts.json is not valid JSON.")
            return

    # If the JSON is just a single dictionary, wrap it in a list so we can loop it
    if isinstance(posts, dict):
        # If your JSON is wrapped in a parent key like {"data": [...]}, adjust this:
        posts = posts.get("data", [posts]) 

    print(f"Found {len(posts)} posts. Beginning ingestion pipeline test...\n")
    
    # Loop through and send each post to the Flask webhook
    for i, post in enumerate(posts, 1):
        author = post.get('author', 'Unknown')
        print(f"[{i}/{len(posts)}] Pushing post by '{author}'...")
        
        try:
            response = requests.post(ENDPOINT, json=post)
            
            if response.status_code in [200, 201]:
                data = response.json()
                if data.get("status") == "skipped":
                    print(f"  -> Skipped (Duplicate Hash)")
                else:
                    print(f"  -> Success: {data.get('file')}")
            else:
                print(f"  -> Failed (HTTP {response.status_code}): {response.text}")
                
        except requests.exceptions.ConnectionError:
            print("\n[FATAL] Connection refused. Is orchestrator.py running on port 5001?")
            break
            
        # 1-second delay so we don't overwhelm your local Mac's CPU/RAM 
        # while Ollama, spaCy, and OpenCTI are all running at once.
        time.sleep(1)

    print("\n[+] Mock ingestion complete.")

if __name__ == "__main__":
    push_mock_data()