import spacy
import classy_classification
from typing import Dict, Any

class ThreatClassifier:
    """
    Few-shot classification engine for the TWIP pipeline.
    Categorizes scraped dark web text into specific threat domains.
    """
    def __init__(self):
        # Load a blank English model to serve as the base
        self.nlp = spacy.blank("en")
        
        # High-fidelity training dictionaries (Few-Shot anchors)
        self.threat_categories = {
            "drug_sales": [
                "selling bulk mdma high purity", 
                "fresh pressed pills BTC only",
                "coke straight from the brick shipped discreetly",
                "vendor for weed hash and psychedelics"
            ],
            "financial_fraud": [
                "selling fresh fullz with high credit score", 
                "non-vbv cards high balance dumps with pin",
                "bank logs for sale chase boa",
                "paypal transfers and cloned credit cards"
            ],
            "hacking_services": [
                "rat for hire fully undetectable", 
                "ddos service available botnet for rent",
                "zero day exploit for windows custom malware",
                "database dumps and SQLi vulnerabilities"
            ],
            "weapons": [
                "selling ars and glocks untraceable", 
                "ammo in stock fast shipping",
                "ghost guns no serial numbers",
                "3d printed auto sears and suppressors"
            ],
            "csam_references": [
                "trading invite codes for exclusive private boards",
                "looking for new unreleased material mega links",
                "access to premium private photo collections"
            ],
            "benign": [
                "looking for forum recommendations",
                "how to configure i2p router tunnels",
                "is this vendor reliable or a scammer",
                "PGP encryption tutorial for beginners"
            ]
        }
        
        # Inject the classy_classification pipe
        # We use a fast, highly optimized sentence-transformer model
        self.nlp.add_pipe(
            "classy_classification", 
            config={
                "data": self.threat_categories, 
                "model": "sentence-transformers/all-MiniLM-L6-v2",
                "device": "cpu" # Ensures stable execution on local hardware
            }
        )

    def classify_text(self, text: str) -> Dict[str, Any]:
        """
        Processes the text and returns the top threat category 
        along with the confidence distribution.
        """
        doc = self.nlp(text)
        
        # classy_classification injects probabilities into doc._.cats
        scores = doc._.cats
        
        # Identify the category with the highest probability
        top_category = max(scores, key=scores.get)
        
        return {
            "top_category": top_category,
            "confidence": round(scores[top_category], 4),
            "all_scores": {k: round(v, 4) for k, v in scores.items()}
        }

if __name__ == "__main__":
    classifier = ThreatClassifier()
    
    sample_posts = [
        "Need a reliable supplier for 100g of pure coke. Escrow only.",
        "Selling Chase bank logs with email access. $500 balance minimum.",
        "Can anyone recommend a good VPN for routing through Tor?"
    ]
    
    print("Threat Classification Results:\n" + "="*30)
    for post in sample_posts:
        print(f"\nPost: '{post}'")
        result = classifier.classify_text(post)
        print(f"Flagged As: {result['top_category'].upper()} (Confidence: {result['confidence']})")