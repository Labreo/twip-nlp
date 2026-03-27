import json
import requests
import time
import os
import glob

# ─────────────────────────────────────────────────────────────────────────────
# TWIP Input Pusher
# Reads individual JSON files from /input (dropped by auto_ingester.py)
# and sends them one by one to the Flask orchestrator on port 5001.
#
# Use this after running auto_ingester.py on real ACHE crawler data.
# For the mock/demo dataset use mock_crawler.py instead.
# ─────────────────────────────────────────────────────────────────────────────

ENDPOINT = "http://localhost:5001/ingest"
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
INPUT_DIR = os.path.join(PROJECT_ROOT, "input")
DELAY_SECONDS = 5  # i2P data is slow — give Ollama time to breathe


def push_input_folder():
    # Find all JSON files in input/ — sorted by name so highest-score
    # files (hit_cybercrime_9pts_...) are processed first
    json_files = sorted(
        glob.glob(os.path.join(INPUT_DIR, "*.json")),
        reverse=True  # descending = highest threat score first
    )

    if not json_files:
        print(f"[!] No JSON files found in {INPUT_DIR}")
        print(f"    Run pipeline/auto_ingester.py first to populate it.")
        return

    print(f"[*] Found {len(json_files)} files in /input")
    print(f"[*] Pushing to {ENDPOINT}")
    print(f"[*] Delay between posts: {DELAY_SECONDS}s\n")

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
            failed += 1
            continue

        author = post.get('author', 'Unknown')
        # Show threat score from filename if present
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
            else:
                print(f"  -> Failed (HTTP {response.status_code}): {response.text[:100]}")
                failed += 1

        except requests.exceptions.ConnectionError:
            print("\n[FATAL] Connection refused.")
            print("        Is orchestrator.py running on port 5001?")
            print("        Run: python pipeline/orchestrator.py")
            break
        except requests.exceptions.Timeout:
            print(f"  -> Timeout (Ollama may be overloaded) — skipping")
            failed += 1
            continue

        time.sleep(DELAY_SECONDS)

    # Summary
    print(f"\n{'='*55}")
    print(f"  TWIP INGESTION COMPLETE")
    print(f"{'='*55}")
    print(f"  Processed:  {len(json_files)} files")
    print(f"  Success:    {success} → STIX bundles in /output")
    print(f"  Skipped:    {skipped} (duplicates)")
    print(f"  Failed:     {failed}")
    print(f"{'='*55}")
    if success > 0:
        print(f"\n  OpenCTI pusher will pick up new bundles automatically.")
        print(f"  Check http://localhost:8080 for updated graph.")


if __name__ == "__main__":
    push_input_folder()
