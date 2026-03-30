import json
import requests
import time
import os
import glob

# ─────────────────────────────────────────────────────────────────────────────
# TWIP Input Pusher (DAEMON MODE)
# Continually watches /input (dropped by auto_ingester.py)
# and sends them one by one to the Flask orchestrator on port 5001.
# ─────────────────────────────────────────────────────────────────────────────

ENDPOINT = "http://localhost:5001/ingest"
# Adjusting PROJECT_ROOT assuming this script is in the root directory
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(PROJECT_ROOT, "input")
DELAY_SECONDS = 5  # i2P data is slow — give Ollama time to breathe

def get_score(filepath):
    """Helper to accurately sort by threat score in the filename."""
    filename = os.path.basename(filepath)
    try:
        parts = filename.split('_')
        for part in parts:
            if part.endswith('pts'):
                return int(part.replace('pts', ''))
    except:
        pass
    return 0

def push_input_folder():
    os.makedirs(INPUT_DIR, exist_ok=True)
    
    print("============================================================")
    print(" TWIP INPUT PUSHER - WATCH MODE LIVE")
    print("============================================================")
    print(f"[*] Watching directory: {INPUT_DIR}")
    print(f"[*] Pushing to: {ENDPOINT}")
    print(f"[*] Delay between posts: {DELAY_SECONDS}s\n")

    while True:
        # Find all JSON files and sort by threat score (highest first)
        json_files = glob.glob(os.path.join(INPUT_DIR, "*.json"))
        
        if not json_files:
            # If folder is empty, wait quietly in the background
            time.sleep(DELAY_SECONDS)
            continue

        # Sort highest threat score first
        json_files.sort(key=get_score, reverse=True)

        print(f"\n[*] Incoming Batch! Found {len(json_files)} files in /input")

        success = 0
        skipped = 0
        failed = 0

        for i, filepath in enumerate(json_files, 1):
            filename = os.path.basename(filepath)

            try:
                with open(filepath, 'r', encoding='utf-8') as f:
                    post = json.load(f)
            except (json.JSONDecodeError, IOError) as e:
                print(f"[{i}/{len(json_files)}] SKIP {filename} — unreadable: {e}")
                os.remove(filepath) # Remove corrupted file
                failed += 1
                continue

            # Extract threat score for terminal UI
            score_hint = ""
            if "pts" in filename:
                parts = filename.split("_")
                for part in parts:
                    if "pts" in part:
                        score_hint = f" [{part}]"
                        break

            print(f"[{i}/{len(json_files)}] {filename}{score_hint}")

            try:
                response = requests.post(ENDPOINT, json=post, timeout=120)

                if response.status_code in [200, 201]:
                    data = response.json()
                    status = data.get("status")

                    if status == "skipped":
                        reason = data.get("reason", "unknown")
                        print(f"  -> Skipped ({reason})")
                        skipped += 1
                    else:
                        category = data.get("category", "?")
                        urgency = data.get("urgency", 0)
                        bundle = data.get("file", "?")
                        ollama_ran = data.get("ollama_ran", False)
                        ollama_tag = "LLM✓" if ollama_ran else "LLM skipped"
                        print(f"  -> ✓ {bundle} | {category} | urgency {urgency}/10 | {ollama_tag}")
                        success += 1
                        
                    # CRITICAL: Delete the file after it's been sent so it isn't processed again
                    os.remove(filepath)
                    
                else:
                    print(f"  -> Failed (HTTP {response.status_code}): {response.text[:100]}")
                    failed += 1
                    # We do not delete the file here, so it can be retried on the next loop

            except requests.exceptions.ConnectionError:
                print("\n[FATAL] Connection refused.")
                print("        Is orchestrator.py running on port 5001?")
                break # Break out of the batch loop and wait for Flask to recover
            except requests.exceptions.Timeout:
                print(f"  -> Timeout (Ollama may be overloaded) — skipping for now")
                failed += 1
                continue

            time.sleep(DELAY_SECONDS)

        # Batch Summary
        if success > 0 or skipped > 0 or failed > 0:
            print(f"\n{'='*55}")
            print(f"  BATCH COMPLETE")
            print(f"{'='*55}")
            print(f"  Processed:  {len(json_files)} files")
            print(f"  Success:    {success} → STIX bundles in /output")
            print(f"  Skipped:    {skipped} (duplicates)")
            print(f"  Failed:     {failed} (will retry)")
            print(f"{'='*55}")
            print(f"[*] Waiting for next batch from auto_ingester...\n")

if __name__ == "__main__":
    push_input_folder()