import os
import json
import re

INPUT_FILE = "decoded_view.txt"
OUTPUT_DIR = "./input"

# 1. Comprehensive Threat Dictionaries (Mapped to your Phase 1 Proposal categories)
THREAT_CATEGORIES = {
    "cybercrime": ["hack", "exploit", "0day", "ddos", "botnet", "malware", "ransomware", "breach", "leak", "password", "shell", "cve-"],
    "financial_fraud": ["cvv", "fullz", "dump", "carding", "paypal", "skimmer", "bank", "ssn", "laundering", "counterfeit"],
    "drugs_narcotics": ["weed", "cocaine", "heroin", "meth", "fentanyl", "mdma", "lsd", "vendor", "gram", "ounce", "kilo"],
    "weapons": ["glock", "ak-47", "ar-15", "ammunition", "silencer", "suppressor", "ghost gun", "firearm", "caliber"],
    "commerce_forum": ["buy", "sell", "escrow", "vendor", "feedback", "pgp", "register", "login", "captcha", "price", "usd"]
}

# 2. Regex Patterns for Cryptocurrency Wallet Extraction
CRYPTO_PATTERNS = {
    "BTC": r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z0-9]{39,59})\b',
    "XMR": r'\b(4[0-9AB][1-9A-HJ-NP-Za-km-z]{93})\b',
    "ETH": r'\b(0x[a-fA-F0-9]{40})\b'
}

os.makedirs(OUTPUT_DIR, exist_ok=True)

def process_i2p_signals():
    print(f"[*] Initializing comprehensive threat filter on {INPUT_FILE}...")
    
    try:
        with open(INPUT_FILE, 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[-] Error: Could not find {INPUT_FILE}.")
        return

    # Split the text blocks based on the separator from our decoding script
    blocks = content.split("================================================================================")
    hits = 0

    for block in blocks:
        if not block.strip():
            continue
            
        lines = block.strip().split('\n')
        url_line = lines[0]
        text_content = '\n'.join(lines[1:]).strip()
        
        # Clean up excessive spaces and newlines
        text_content = re.sub(r'\s+', ' ', text_content) 
        text_lower = text_content.lower()
        
        # Skip short, useless posts (like basic server errors or empty pages)
        if len(text_content) < 150:
            continue

        url = url_line.replace("=== URL: ", "").replace(" ===", "").strip()
        
        # Phase 1: Categorize the text based on keywords
        detected_categories = []
        for category, keywords in THREAT_CATEGORIES.items():
            if any(keyword in text_lower for keyword in keywords):
                detected_categories.append(category)

        # Phase 2: Hunt for Crypto Addresses using Regex
        detected_crypto = {}
        for coin, pattern in CRYPTO_PATTERNS.items():
            matches = re.findall(pattern, text_content)
            if matches:
                detected_crypto[coin] = list(set(matches)) # Store unique addresses only

        # Phase 3: If it hits our filters, save it as a structured payload
        if detected_categories or detected_crypto:
            payload = {
                "url": url,
                "author": "Unknown_I2P_Actor",
                "content": text_content,
                "pre_analysis_metadata": {
                    "tags": detected_categories,
                    "crypto_wallets_found": detected_crypto,
                    "character_count": len(text_content)
                }
            }
            
            # Name the output file intelligently based on its primary threat category
            primary_tag = detected_categories[0] if detected_categories else "crypto_only"
            filename = os.path.join(OUTPUT_DIR, f"i2p_hit_{primary_tag}_{hits}.json")
            
            with open(filename, 'w', encoding='utf-8') as out_f:
                json.dump(payload, out_f, indent=4)
                
            hits += 1

    print(f"[+] Filtering complete!")
    print(f"[*] Successfully isolated {hits} high-signal posts from the raw noise.")
    print(f"[*] Data is pre-tagged and ready for Llama 3 in the '{OUTPUT_DIR}' directory.")

if __name__ == "__main__":
    process_i2p_signals()