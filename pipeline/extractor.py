import re
import spacy
from typing import Dict, List, Any

class DarkWebExtractor:
    """
    Handles regex extraction and Named Entity Recognition (NER) 
    for the TWIP pipeline.
    """
    def __init__(self):
        # Comprehensive regex for identifying various crypto wallets 
        self.crypto_patterns = {
            "bitcoin": r"\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b",
            "ethereum": r"\b0x[a-fA-F0-9]{40}\b",
            "monero": r"\b([48][0-9a-zA-Z]{94}|[48][0-9a-zA-Z]{105})\b" 
        }
        
        # Load the highly accurate Transformer-based spaCy model [cite: 36]
        try:
            self.nlp = spacy.load("en_core_web_trf")
        except OSError:
            print("Error: Transformer model not found. Run: python -m spacy download en_core_web_trf")
            self.nlp = spacy.blank("en")
            
    def extract_crypto_wallets(self, text: str) -> Dict[str, List[str]]:
        """Scans unstructured text for cryptocurrency wallet addresses."""
        wallets = {"bitcoin": [], "ethereum": [], "monero": []}
        for currency, pattern in self.crypto_patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                # Use set() to remove duplicate mentions of the same address
                wallets[currency] = list(set(matches))
        return wallets
        
    def extract_entities(self, text: str) -> List[Dict[str, str]]:
        """Extracts high-value entities using Transformer NER."""
        doc = self.nlp(text)
        entities = []
        
        # Filtering for entities relevant to threat intelligence [cite: 37]
        target_labels = {"PERSON", "ORG", "GPE", "MONEY", "LOC", "FAC"}
        
        for ent in doc.ents:
            if ent.label_ in target_labels:
                entities.append({
                    "text": ent.text, 
                    "label": ent.label_
                })
        return entities

    def process_text(self, text: str) -> Dict[str, Any]:
        """Entry point to extract all target data from a single post."""
        return {
            "wallets": self.extract_crypto_wallets(text),
            "entities": self.extract_entities(text)
        }

if __name__ == "__main__":
    # Local testing block
    sample_post = """
    Looking for a reliable vendor in London. I need 50g of the usual. 
    Will only pay via XMR to this address: 44AFFq5kSiGBoZ4NMDwYtN18obc8AemS33nMBJoWQ31m2hLh4Q8Fz4B7T8r9P9bZz7g5s2V
    Alternatively, send BTC to bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq. 
    Contact JohnDoe99 or message the Syndicate.
    """
    
    extractor = DarkWebExtractor()
    results = extractor.process_text(sample_post)
    
    print("Extraction Results:")
    print(results)