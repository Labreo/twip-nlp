import os
import shutil
import time
import glob

# ─────────────────────────────────────────────────────────────────────────────
# TWIP Data Watcher
# Watches Downloads/data for new .deflate files from Abdullah's crawler
# and moves them into twip-nlp/data/ for the pipeline to process
# ─────────────────────────────────────────────────────────────────────────────

# Source — where Abdullah's crawler drops data
SOURCE_DIR = os.path.join(os.path.expanduser('~'), 'Downloads', 'data')

# Destination — twip-nlp data folder
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DEST_DIR = os.path.join(SCRIPT_DIR, 'data')

# How often to check (seconds)
POLL_INTERVAL = 5

os.makedirs(SOURCE_DIR, exist_ok=True)
os.makedirs(DEST_DIR, exist_ok=True)

def is_deflate_file(filepath):
    """Check if file has .deflate extension."""
    return os.path.isfile(filepath) and filepath.lower().endswith('.deflate')

def is_file_ready(filepath, wait_time=1):
    """
    Check if file is fully written by comparing size over a short interval.
    Prevents moving half-written files.
    """
    try:
        size1 = os.path.getsize(filepath)
        time.sleep(wait_time)
        size2 = os.path.getsize(filepath)
        return size1 == size2
    except:
        return False

def watch():
    print(f"[*] TWIP Data Watcher started")
    print(f"[*] Watching: {SOURCE_DIR}")
    print(f"[*] Sending to: {DEST_DIR}")
    print(f"[*] Polling every {POLL_INTERVAL} seconds\n")

    seen = set()

    while True:
        # Only look for .deflate files
        files = glob.glob(os.path.join(SOURCE_DIR, '*.deflate'))

        for filepath in files:
            filename = os.path.basename(filepath)

            # Skip already processed files
            if filename in seen:
                continue

            # Double-check it's really a .deflate file
            if not is_deflate_file(filepath):
                print(f"[!] Ignored non-.deflate file: {filename}")
                continue

            # Make sure file is fully written before moving
            if not is_file_ready(filepath):
                print(f"[~] Waiting for file to finish writing: {filename}")
                continue

            dest_path = os.path.join(DEST_DIR, filename)

            try:
                shutil.move(filepath, dest_path)
                seen.add(filename)
                print(f"[+] Moved: {filename} → data/")
            except Exception as e:
                print(f"[-] Failed to move {filename}: {e}")

        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    watch()