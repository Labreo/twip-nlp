import os
import glob
import zlib
import json
import base64
import re
import time
import warnings
from bs4 import BeautifulSoup, XMLParsedAsHTMLWarning

warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
INPUT_DIR = os.path.join(PROJECT_ROOT, "input")

MIN_CHAR_LIMIT = 150
MAX_CHAR_LIMIT = 5000
MIN_THREAT_SCORE = 3
POLL_INTERVAL = 5  # seconds between folder checks
FILE_STABLE_WAIT = 2  # seconds to confirm file finished writing

# ─────────────────────────────────────────────────────────────────────────────
# TIER 1 — HARD SIGNALS (each match = 3 points)
# ─────────────────────────────────────────────────────────────────────────────
TIER1_KEYWORDS = {
    "drugs": [
        "fentanyl", "heroin", "methamphetamine", "mdma crystals",
        "cocaine hydrochloride", "pressed pills", "bulk mdma",
        "stealth shipping", "vacuum sealed drugs", "drug vendor",
        "darknet market", "finalize early", "fe only", "bb forums", "breaking bad"
    ],
    "weapons": [
        "ghost gun", "untraceable firearm", "serialized removed",
        "full auto conversion", "suppressor for sale", "ak-47 parts kit",
        "ar-15 lower", "illegal mags", "weapons vendor", "3d printing", ".stl"
    ],
    "cybercrime": [
        "ransomware affiliate", "lockbit", "blackcat ransomware",
        "zero-day exploit", "0day for sale", "rat builder",
        "remote access trojan", "cobalt strike beacon",
        "credential dumping", "mimikatz", "reverse shell",
        "c2 server", "command and control", "botnet for hire",
        "ddos for hire", "stresser service", "crypter fud"
    ],
    "financial_fraud": [
        "fullz", "non-vbv", "track 1 and 2", "cc dumps",
        "money mule", "carding", "bank account logs",
        "western union exploit", "cashout method",
        "btc tumbling", "coin mixer", "money laundering",
        "counterfeit bills", "fake id vendor", "boomer"
    ],
    "csam_references": [
        "trading invite codes", "unreleased material mega",
        "premium private photo collections", "mega folder link",
        "exclusive private board", "underage content", "loli", "shota", "cunny","pedo"
    ],
    "exploitation": [
        "cve-202",
        "weaponized exploit", "proof of concept exploit",
        "privilege escalation", "lateral movement",
        "active directory dump", "domain controller"
    ]
}

# ─────────────────────────────────────────────────────────────────────────────
# TIER 2 — MEDIUM SIGNALS (each match = 1 point)
# ─────────────────────────────────────────────────────────────────────────────
TIER2_KEYWORDS = [
    "escrow", "pgp key", "vendor", "stealth", "anonymous",
    "dark web", "onion", "i2p", "tox id", "jabber",
    "bulk order", "minimum order", "trusted vendor",
    "no logs", "encrypted", "finalize", "dispute",
    "feedback", "verified", "dox", "doxxing",
    "exploit", "payload", "persistence", "evasion",
    "keylogger", "screencap", "bruteforce", "sqlmap"
]

EXCLUSION_PATTERNS = [
    # General Web Noise
    r"copyright \d{4}", r"privacy policy", r"terms of service",
    r"all rights reserved", r"cookie policy", r"subscribe to our newsletter",
    r"wordpress", r"powered by", r"404 not found", r"403 forbidden",
    
    # --- NEW: The CTF / Educational Kill Switch ---
    r"writeup", r"hackthebox", r"tryhackme", r"capture the flag", r"ctf",
    r"tutorial", r"course", r"training", r"walkthrough",
    
    # --- NEW: The Forum Admin Kill Switch ---
    r"moderation requests", r"abuse reports", r"ban appeal", 
    r"forum rules", r"contact the admin", r"post removed"
]

CRYPTO_PATTERNS = {
    "BTC": r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b',
    "XMR": r'\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b',
    "ETH": r'\b(0x[a-fA-F0-9]{40})\b'
}

os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(INPUT_DIR, exist_ok=True)


# ─────────────────────────────────────────────────────────────────────────────
# DECOMPRESSION — streaming, handles large and multi-stream zlib files
# ─────────────────────────────────────────────────────────────────────────────
def decompress_streaming(data: bytes) -> bytes:
    if len(data) >= 2 and data[0] == 0x78:
        d = zlib.decompressobj(zlib.MAX_WBITS)           # zlib header
    elif data[:2] == b'\x1f\x8b':
        d = zlib.decompressobj(zlib.MAX_WBITS | 16)      # gzip header
    else:
        d = zlib.decompressobj(-zlib.MAX_WBITS)          # raw deflate

    chunks = []
    chunk_size = 1024 * 1024  # 1 MB

    for i in range(0, len(data), chunk_size):
        chunks.append(d.decompress(data[i:i + chunk_size]))
    chunks.append(d.flush())

    return b''.join(chunks)


def score_content(text: str) -> tuple:
    text_lower = text.lower()
    score = 0
    matched_tier1 = {}
    matched_tier2 = []

    for pattern in EXCLUSION_PATTERNS:
        if re.search(pattern, text_lower):
            return -999, {}, []

    for category, keywords in TIER1_KEYWORDS.items():
        hits = [kw for kw in keywords if kw in text_lower]
        if hits:
            matched_tier1[category] = hits
            score += len(hits) * 3

    for keyword in TIER2_KEYWORDS:
        if keyword in text_lower:
            matched_tier2.append(keyword)
            score += 1

    for _, pattern in CRYPTO_PATTERNS.items():
        if re.search(pattern, text):
            score += 2

    if len(matched_tier1) >= 2:
        score += 3

    return score, matched_tier1, matched_tier2


def extract_metadata(text: str) -> dict:
    metadata = {}
    wallets = {}

    for coin, pattern in CRYPTO_PATTERNS.items():
        found = list(set(re.findall(pattern, text)))
        if found:
            wallets[coin] = found
    if wallets:
        metadata["crypto_wallets"] = wallets

    tox_ids = re.findall(r'\b[A-Fa-f0-9]{64}\b', text)
    if tox_ids:
        metadata["tox_ids"] = list(set(tox_ids))

    if "BEGIN PGP PUBLIC KEY" in text:
        metadata["pgp_key_present"] = True

    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text.upper())
    if cves:
        metadata["cves"] = list(set(cves))

    return metadata


def parse_html_safe(html: str) -> str:
    for parser in ('lxml', 'html.parser'):
        try:
            soup = BeautifulSoup(html, parser)
            for tag in soup(["script", "style", "nav", "footer", "header"]):
                tag.extract()
            return re.sub(r'\s+', ' ', soup.get_text(separator=' ', strip=True))
        except Exception:
            continue
    return ""


def delete_source_file(file_path: str):
    filename = os.path.basename(file_path)
    try:
        os.remove(file_path)
        print(f"[*] Deleted source file: {filename}")
    except Exception as e:
        print(f"[-] Could not delete source file {filename}: {e}")


def find_deflate_files_in_data():
    return sorted(
        glob.glob(os.path.join(DATA_DIR, '*.deflate')),
        key=os.path.getctime
    )


def is_file_stable(file_path: str, wait_seconds: int = FILE_STABLE_WAIT) -> bool:
    """
    Prevents processing files that are still being written.
    """
    try:
        size1 = os.path.getsize(file_path)
        time.sleep(wait_seconds)
        size2 = os.path.getsize(file_path)
        return size1 == size2 and size1 > 0
    except Exception:
        return False


def process_data(deflate_path) -> bool:
    print(f"[*] Found ACHE data: {os.path.basename(deflate_path)}")
    print("[*] Unpacking binary and decoding Base64 in memory...")

    try:
        with open(deflate_path, 'rb') as f:
            compressed_data = f.read()
    except Exception as e:
        print(f"[-] Could not read file: {e}")
        return False

    try:
        raw_bytes = decompress_streaming(compressed_data)
        print(f"[*] Decompressed successfully ({len(raw_bytes):,} bytes)")
    except zlib.error as e:
        print(f"[-] ERROR: Could not decompress {os.path.basename(deflate_path)}: {e}")
        print(f"    File size : {len(compressed_data):,} bytes")
        print(f"    First 32B : {compressed_data[:32].hex()}")
        print(f"    Skipping this file and continuing...\n")
        return False

    raw_text = raw_bytes.decode('utf-8', errors='ignore')

    hits = 0
    skipped_noise = 0
    skipped_length = 0
    skipped_excluded = 0
    score_distribution = {"0-2": 0, "3-5": 0, "6-9": 0, "10+": 0}

    print(f"[*] Running scored threat filter (min score: {MIN_THREAT_SCORE})...")

    for line in (line for line in raw_text.splitlines() if line.strip()):
        try:
            data = json.loads(line)
            url = data.get("url", "unknown_url")
            b64_content = data.get("content", "")

            if not b64_content:
                continue

            html = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
            text_content = parse_html_safe(html)

            if not text_content:
                skipped_length += 1
                continue

            if len(text_content) < MIN_CHAR_LIMIT:
                skipped_length += 1
                continue
            if len(text_content) > MAX_CHAR_LIMIT:
                text_content = text_content[:MAX_CHAR_LIMIT]

            score, tier1_matches, tier2_matches = score_content(text_content)

            if score < 0:
                skipped_excluded += 1
                continue
            elif score < 3:
                score_distribution["0-2"] += 1
                skipped_noise += 1
                continue
            elif score < 6:
                score_distribution["3-5"] += 1
            elif score < 10:
                score_distribution["6-9"] += 1
            else:
                score_distribution["10+"] += 1

            if score < MIN_THREAT_SCORE:
                skipped_noise += 1
                continue

            ioc_metadata = extract_metadata(text_content)
            primary_category = (
                list(tier1_matches.keys())[0]
                if tier1_matches else "crypto_only"
            )

            payload = {
                "url": url,
                "author": "Unknown_I2P_Actor",
                "content": text_content,
                "pre_analysis_metadata": {
                    "threat_score": score,
                    "tier1_matches": tier1_matches,
                    "tier2_signals": tier2_matches[:10],
                    "primary_category": primary_category,
                    "iocs": ioc_metadata,
                    "character_count": len(text_content)
                }
            }

            out_file = os.path.join(
                INPUT_DIR,
                f"hit_{primary_category}_{score:03d}pts_{int(time.time())}_{hits}.json"
            )

            with open(out_file, 'w', encoding='utf-8') as out_f:
                json.dump(payload, out_f, indent=4)

            hits += 1

        except Exception as e:
            print(f"[-] Skipping malformed line: {e}")
            continue

    print(f"\n{'='*55}")
    print(f"  TWIP PRE-FILTER RESULTS")
    print(f"{'='*55}")
    print(f"  Passed filter:        {hits} posts → /input")
    print(f"  Skipped (too short):  {skipped_length}")
    print(f"  Skipped (excluded):   {skipped_excluded}  (login pages, 404s etc)")
    print(f"  Skipped (low score):  {skipped_noise}  (score < {MIN_THREAT_SCORE})")
    print(f"\n  Score distribution of passing posts:")
    for band, count in score_distribution.items():
        bar = "█" * min(count, 40)
        print(f"    {band:>5} pts: {bar} {count}")
    print(f"{'='*55}")

    if hits > 0:
        print(f"\n  Next step: python input_pusher.py")
        print(f"  Files sorted by score — highest threat posts processed first.")

    return True


def watch_data_folder():
    print("=" * 60)
    print(" TWIP AUTO INGESTER WATCH MODE")
    print("=" * 60)
    print(f"[*] Watching folder: {DATA_DIR}")
    print(f"[*] Poll interval: {POLL_INTERVAL}s")
    print(f"[*] Waiting {FILE_STABLE_WAIT}s to confirm file is fully written")
    print("[*] Press Ctrl+C to stop.\n")

    while True:
        try:
            deflate_files = find_deflate_files_in_data()

            if deflate_files:
                print(f"\n[*] Detected {len(deflate_files)} file(s) in data/")
                for deflate_path in deflate_files:
                    filename = os.path.basename(deflate_path)

                    print(f"\n{'='*55}")
                    print(f"  Checking: {filename}")
                    print(f"{'='*55}")

                    if not is_file_stable(deflate_path):
                        print(f"[-] File still being written, skipping for now: {filename}")
                        continue

                    print(f"[*] File is stable. Processing: {filename}")
                    success = process_data(deflate_path)

                    if success:
                        delete_source_file(deflate_path)
                    else:
                        print(f"[-] Processing failed, keeping file for retry: {filename}")

            time.sleep(POLL_INTERVAL)

        except KeyboardInterrupt:
            print("\n[*] Watcher stopped by user.")
            break
        except Exception as e:
            print(f"[-] Watch loop error: {e}")
            time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    watch_data_folder()