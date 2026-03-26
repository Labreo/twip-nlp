import os
import glob
import shutil
import py7zr
import zlib
import json
import base64
import re
import time
from bs4 import BeautifulSoup

# --- Configuration ---
DOWNLOADS_DIR = os.path.join(os.path.expanduser('~'), 'Downloads')
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMP_EXTRACT_DIR = os.path.join(PROJECT_ROOT, "temp_ache_raw")
INPUT_DIR = os.path.join(PROJECT_ROOT, "input")
ARCHIVE_PASSWORD = "bitsHACK"

MIN_CHAR_LIMIT = 150
MAX_CHAR_LIMIT = 5000

# ─────────────────────────────────────────────────────────────────────────────
# TIER 1 — HARD SIGNALS (each match = 3 points)
# These are unambiguous. A normal website will never say these.
# ─────────────────────────────────────────────────────────────────────────────
TIER1_KEYWORDS = {
    "drugs": [
        "fentanyl", "heroin", "methamphetamine", "mdma crystals",
        "cocaine hydrochloride", "pressed pills", "bulk mdma",
        "stealth shipping", "vacuum sealed drugs", "drug vendor",
        "darknet market", "finalize early", "fe only"
    ],
    "weapons": [
        "ghost gun", "untraceable firearm", "serialized removed",
        "full auto conversion", "suppressor for sale", "ak-47 parts kit",
        "ar-15 lower", "illegal mags", "weapons vendor"
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
        "counterfeit bills", "fake id vendor"
    ],
    "exploitation": [
        "cve-202", "cve-202",  # broad CVE match for recent years
        "weaponized exploit", "proof of concept exploit",
        "privilege escalation", "lateral movement",
        "active directory dump", "domain controller"
    ]
}

# ─────────────────────────────────────────────────────────────────────────────
# TIER 2 — MEDIUM SIGNALS (each match = 1 point)
# These appear in legitimate contexts too, but raise suspicion in combination
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

# ─────────────────────────────────────────────────────────────────────────────
# TIER 3 — HARD EXCLUSIONS
# If any of these dominate the page, it's almost certainly not a threat post
# ─────────────────────────────────────────────────────────────────────────────
EXCLUSION_PATTERNS = [
    r"copyright \d{4}",
    r"privacy policy",
    r"terms of service",
    r"all rights reserved",
    r"cookie policy",
    r"subscribe to our newsletter",
    r"wordpress",
    r"powered by",
    r"404 not found",
    r"403 forbidden",
    r"access denied",
    r"cloudflare",
    r"please enable javascript",
    r"this site requires javascript",
]

# ─────────────────────────────────────────────────────────────────────────────
# CRYPTO PATTERNS
# ─────────────────────────────────────────────────────────────────────────────
CRYPTO_PATTERNS = {
    "BTC": r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b',
    "XMR": r'\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b',
    "ETH": r'\b(0x[a-fA-F0-9]{40})\b'
}

# Minimum score to pass the filter — tune this for precision vs recall
# 3 = at least one Tier 1 keyword OR three Tier 2 keywords
# 6 = at least two Tier 1 keywords (very strict)
MIN_THREAT_SCORE = 3

os.makedirs(TEMP_EXTRACT_DIR, exist_ok=True)
os.makedirs(INPUT_DIR, exist_ok=True)


def score_content(text: str) -> tuple[int, dict, list]:
    """
    Returns (score, matched_tier1, matched_tier2).
    Score >= MIN_THREAT_SCORE passes the filter.
    """
    text_lower = text.lower()
    score = 0
    matched_tier1 = {}
    matched_tier2 = []

    # Hard exclusion check — bail immediately
    for pattern in EXCLUSION_PATTERNS:
        if re.search(pattern, text_lower):
            return -999, {}, []

    # Tier 1 scoring
    for category, keywords in TIER1_KEYWORDS.items():
        hits = [kw for kw in keywords if kw in text_lower]
        if hits:
            matched_tier1[category] = hits
            score += len(hits) * 3  # 3 points each

    # Tier 2 scoring
    for keyword in TIER2_KEYWORDS:
        if keyword in text_lower:
            matched_tier2.append(keyword)
            score += 1  # 1 point each

    # Bonus: crypto wallet found — strong signal of dark web commerce
    for coin, pattern in CRYPTO_PATTERNS.items():
        if re.search(pattern, text):
            score += 2

    # Bonus: multiple categories detected — cross-domain threat actor
    if len(matched_tier1) >= 2:
        score += 3

    return score, matched_tier1, matched_tier2


def extract_metadata(text: str) -> dict:
    """Extract crypto wallets and communications IOCs."""
    metadata = {}

    # Crypto wallets
    wallets = {}
    for coin, pattern in CRYPTO_PATTERNS.items():
        found = list(set(re.findall(pattern, text)))
        if found:
            wallets[coin] = found
    if wallets:
        metadata["crypto_wallets"] = wallets

    # Tox IDs (64 char hex)
    tox_ids = re.findall(r'\b[A-Fa-f0-9]{64}\b', text)
    if tox_ids:
        metadata["tox_ids"] = list(set(tox_ids))

    # PGP key blocks
    if "BEGIN PGP PUBLIC KEY" in text:
        metadata["pgp_key_present"] = True

    # CVE references
    cves = re.findall(r'CVE-\d{4}-\d{4,7}', text.upper())
    if cves:
        metadata["cves"] = list(set(cves))

    return metadata


def find_latest_archive():
    list_of_files = glob.glob(os.path.join(DOWNLOADS_DIR, '*.7z'))
    if not list_of_files:
        return None
    return max(list_of_files, key=os.path.getctime)


def extract_and_find_deflate(archive_path):
    print(f"[*] Extracting {os.path.basename(archive_path)}...")
    with py7zr.SevenZipFile(archive_path, mode='r', password=ARCHIVE_PASSWORD) as z:
        z.extractall(path=TEMP_EXTRACT_DIR)

    for root, _, files in os.walk(TEMP_EXTRACT_DIR):
        for file in files:
            if file.endswith('.deflate'):
                return os.path.join(root, file)
    return None


def process_data(deflate_path):
    print(f"[*] Found ACHE data: {os.path.basename(deflate_path)}")
    print("[*] Unpacking binary and decoding Base64 in memory...")

    with open(deflate_path, 'rb') as f:
        compressed_data = f.read()

    try:
        raw_bytes = zlib.decompress(compressed_data, zlib.MAX_WBITS | 32)
    except zlib.error:
        raw_bytes = zlib.decompress(compressed_data, -15)

    raw_text = raw_bytes.decode('utf-8', errors='ignore')

    hits = 0
    skipped_noise = 0
    skipped_length = 0
    skipped_excluded = 0

    score_distribution = {"0-2": 0, "3-5": 0, "6-9": 0, "10+": 0}

    print(f"[*] Running scored threat filter (min score: {MIN_THREAT_SCORE})...")

    for line in raw_text.split('\n'):
        if not line.strip():
            continue

        try:
            data = json.loads(line)
            url = data.get("url", "unknown_url")
            b64_content = data.get("content", "")

            if not b64_content:
                continue

            html = base64.b64decode(b64_content).decode('utf-8', errors='ignore')
            soup = BeautifulSoup(html, 'html.parser')
            for tag in soup(["script", "style", "nav", "footer", "header"]):
                tag.extract()
            text_content = re.sub(r'\s+', ' ', soup.get_text(separator=' ', strip=True))

            # Length guard
            if len(text_content) < MIN_CHAR_LIMIT:
                skipped_length += 1
                continue
            if len(text_content) > MAX_CHAR_LIMIT:
                text_content = text_content[:MAX_CHAR_LIMIT]

            # Score it
            score, tier1_matches, tier2_matches = score_content(text_content)

            # Track score distribution
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

            # Extract IOC metadata
            ioc_metadata = extract_metadata(text_content)

            # Determine primary category
            primary_category = list(tier1_matches.keys())[0] if tier1_matches else "crypto_only"

            payload = {
                "url": url,
                "author": "Unknown_I2P_Actor",
                "content": text_content,
                "pre_analysis_metadata": {
                    "threat_score": score,
                    "tier1_matches": tier1_matches,
                    "tier2_signals": tier2_matches[:10],  # top 10
                    "primary_category": primary_category,
                    "iocs": ioc_metadata,
                    "character_count": len(text_content)
                }
            }

            out_file = os.path.join(
                INPUT_DIR,
                f"hit_{primary_category}_{score}pts_{int(time.time())}_{hits}.json"
            )
            with open(out_file, 'w', encoding='utf-8') as out_f:
                json.dump(payload, out_f, indent=4)
            hits += 1

        except Exception:
            continue

    # Summary
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
        print(f"\n  Files named by category + score:")
        print(f"  e.g. hit_cybercrime_9pts_... → highest priority")
        print(f"  Sort /input by filename to demo highest-threat posts first.")

    shutil.rmtree(TEMP_EXTRACT_DIR)
    print("\n[*] Cleaned up temporary extraction folders.")


if __name__ == "__main__":
    latest_archive = find_latest_archive()
    if latest_archive:
        print(f"[*] Found crawler drop: {latest_archive}")
        deflate_file = extract_and_find_deflate(latest_archive)
        if deflate_file:
            process_data(deflate_file)
        else:
            print("[-] Could not find a .deflate file inside the archive.")
    else:
        print("[-] No .7z archives found in Downloads folder.")
