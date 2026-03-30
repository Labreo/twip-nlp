import os
import shutil
import time
import glob

# ─────────────────────────────────────────────────────────────────────────────
# TWIP Data Watcher
# Watches Downloads/data for new files from Abdullah's crawler
# and moves them into twip-nlp/input/ for the pipeline to process
# ─────────────────────────────────────────────────────────────────────────────

# Source — where Abdullah's crawler drops data
SOURCE_DIR = os.path.join(os.path.expanduser('~'), 'Downloads', 'data')

# Destination — twip-nlp input folder
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEST_DIR = os.path.join(SCRIPT_DIR, 'data')

# How often to check (seconds)
POLL_INTERVAL = 5

os.makedirs(SOURCE_DIR, exist_ok=True)
os.makedirs(DEST_DIR, exist_ok=True)

def watch():
    print(f"[*] TWIP Data Watcher started")
    print(f"[*] Watching: {SOURCE_DIR}")
    print(f"[*] Sending to: {DEST_DIR}")
    print(f"[*] Polling every {POLL_INTERVAL} seconds\n")

    seen = set()

    while True:
        # Find all files in source (any extension)
        files = glob.glob(os.path.join(SOURCE_DIR, '*'))

        for filepath in files:
            filename = os.path.basename(filepath)

            # Skip directories and already processed files
            if os.path.isdir(filepath) or filename in seen:
                continue

            dest_path = os.path.join(DEST_DIR, filename)

            try:
                shutil.move(filepath, dest_path)
                seen.add(filename)
                print(f"[+] Copied: {filename} → data/")
            except Exception as e:
                print(f"[-] Failed to copy {filename}: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    watch()
