import re
import os
import spacy
import requests
from typing import Dict, List, Any
from dotenv import load_dotenv

load_dotenv()
BLOCKCYPHER_TOKEN = os.getenv("BLOCKCYPHER_TOKEN")

class DarkWebExtractor:
    """
    Handles regex extraction, NER, and blockchain enrichment 
    for the TWIP pipeline.
    """
    def __init__(self):
        # Comprehensive regex for identifying various crypto wallets 
        self.crypto_patterns = {
            "bitcoin": r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b",
            "ethereum": r"\b0x[a-fA-F0-9]{40}\b",
            "monero": r"\b([48][0-9a-zA-Z]{94}|[48][0-9a-zA-Z]{105})\b" 
        }
        
        try:
            self.nlp = spacy.load("en_core_web_trf")
        except OSError:
            print("Error: Transformer model not found. Run: python -m spacy download en_core_web_trf")
            self.nlp = spacy.blank("en")
    def extract_cves(self, text: str) -> list:
        """Extracts standard CVE vulnerability identifiers."""
        # Matches formats like CVE-2024-1234 or CVE-2023-123456
        cve_pattern = r"(?i)CVE-\d{4}-\d{4,7}"
        return list(set(re.findall(cve_pattern, text.upper())))

    def extract_tactics_and_malware(self, text: str) -> dict:
        """Quick keyword matching for common tools and malware families."""
        text_lower = text.lower()
        
        known_tools = ["cobalt strike", "mimikatz", "metasploit", "flipper zero", "sqlmap", "burp suite"]
        known_malware = ["lockbit", "ryuk", "emotet", "mirai", "qakbot", "cobaltstrike", "pegasus"]
        
        return {
            "tools": [tool for tool in known_tools if tool in text_lower],
            "malware": [mal for mal in known_malware if mal in text_lower]
        }

    def process_text(self, text: str) -> dict:
        """Entry point to extract all target data and enrich BTC wallets."""
        wallets = self.extract_crypto_wallets(text)
        entities = self.extract_entities(text)
        
        # Pull out Geographic Locations from the spaCy entities
        locations = list(set([ent["text"] for ent in entities if ent["label"] == "GPE"]))
        
        enriched_btc_data = []
        for btc_addr in wallets.get("bitcoin", []):
            print(f"[*] Enriching BTC Wallet: {btc_addr}...")
            enriched_btc_data.append(self.enrich_bitcoin_wallet(btc_addr))
            
        return {
            "wallets": wallets, 
            "entities": entities,
            "locations": locations, # Added Locations
            "cves": self.extract_cves(text), # Added CVEs
            "arsenal": self.extract_tactics_and_malware(text), # Added Malware/Tools
            "enriched_wallets": enriched_btc_data
        }
    def enrich_bitcoin_wallet(self, wallet_address: str) -> dict:
        """Queries BlockCypher API for live Bitcoin wallet statistics using your token."""
        if not BLOCKCYPHER_TOKEN:
            return {"address": wallet_address, "enriched": False, "error": "No API token configured"}
            
        api_url = f"https://api.blockcypher.com/v1/btc/main/addrs/{wallet_address}?token={BLOCKCYPHER_TOKEN}"
        
        try:
            response = requests.get(api_url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                # Convert Satoshis to actual BTC
                balance_btc = data.get('balance', 0) / 100000000
                total_received_btc = data.get('total_received', 0) / 100000000
                
                return {
                    "address": wallet_address,
                    "transaction_count": data.get('n_tx', 0),
                    "balance_btc": balance_btc,
                    "total_received_btc": total_received_btc,
                    "enriched": True
                }
            else:
                return {"address": wallet_address, "enriched": False, "error": f"HTTP {response.status_code}"}
        except Exception as e:
            return {"address": wallet_address, "enriched": False, "error": str(e)}
            
    def extract_crypto_wallets(self, text: str) -> Dict[str, List[str]]:
        """Scans unstructured text for cryptocurrency wallet addresses."""
        wallets = {"bitcoin": [], "ethereum": [], "monero": []}
        for currency, pattern in self.crypto_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                wallets[currency] = list(set(matches))
        return wallets
        
    def extract_entities(self, text: str) -> List[Dict[str, str]]:
        """Extracts high-value entities using Transformer NER."""
        doc = self.nlp(text)
        entities = []
        target_labels = {"PERSON", "ORG", "GPE", "MONEY", "LOC", "FAC"}
        
        for ent in doc.ents:
            if ent.label_ in target_labels:
                entities.append({"text": ent.text, "label": ent.label_})
        return entities

    def process_text(self, text: str) -> Dict[str, Any]:
        """Entry point to extract all target data and enrich BTC wallets."""
        wallets = self.extract_crypto_wallets(text)
        
        # --- NEW: Enrich only Bitcoin wallets ---
        enriched_btc_data = []
        for btc_addr in wallets.get("bitcoin", []):
            print(f"[*] Enriching BTC Wallet: {btc_addr}...")
            enriched_btc_data.append(self.enrich_bitcoin_wallet(btc_addr))
            
        return {
            "wallets": wallets, 
            "entities": self.extract_entities(text),
            "enriched_wallets": enriched_btc_data # Added for the Streamlit Dashboard
        }

if __name__ == "__main__":
    sample_post = "Send BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq to buy."
    extractor = DarkWebExtractor()
    print(extractor.process_text(sample_post))