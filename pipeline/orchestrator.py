import os
import json
import hashlib
from datetime import datetime
from flask import Flask, request, jsonify

# Import your custom modules
from extractor import DarkWebExtractor
from classifier import ThreatClassifier
from llm_analyzer import ThreatLLMAnalyzer
from alias_resolver import AliasResolver

app = Flask(__name__)

# ==========================================
# 1. Initialize Pipeline (Loads Models Once)
# ==========================================
print("Initializing TWIP AI Pipeline... (This may take a minute)")
extractor = DarkWebExtractor()
classifier = ThreatClassifier()
llm_analyzer = ThreatLLMAnalyzer()
alias_resolver = AliasResolver()

# In-memory store for deduplication hashes
seen_hashes = set()

# Ensure output directory exists
# Ensure output directory exists in the root of twip-nlp
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# ==========================================
# 2. The Core Processing Logic
# ==========================================
def generate_content_hash(text: str) -> str:
    """Creates a SHA-256 hash of the text for deduplication."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

@app.route('/ingest', methods=['POST'])
def ingest_data():
    """Webhook endpoint for the ACHE crawler to push scraped data."""
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({"error": "Invalid payload. 'content' field required."}), 400
            
        url = data.get('url', 'unknown_source')
        content = data['content']
        author = data.get('author', 'anonymous')
        
        # --- DEDUPLICATION LAYER ---
        content_hash = generate_content_hash(content)
        if content_hash in seen_hashes:
            print(f"[-] Duplicate skipped from: {url}")
            return jsonify({"status": "skipped", "reason": "duplicate"}), 200
            
        seen_hashes.add(content_hash)
        print(f"[+] Processing new intelligence from: {url}")

        # --- EXECUTE PIPELINE ---
        # 1. Extract IOCs (Regex + NER)
        extracted_data = extractor.process_text(content)
        
        # 2. Classify Threat Domain (Few-Shot)
        classification = classifier.classify_text(content)
        
        # 3. LLM Analysis (Urgency, Sentiment, Trends)
        llm_assessment = llm_analyzer.analyze_urgency(content)
        trends = llm_analyzer.detect_trends(content)
        
        # 4. Resolve Aliases (Cross-Forum Linking)
        alias_data = alias_resolver.process_and_link(author, extracted_data)

        # --- COMPILE STIX-READY OUTPUT ---
        enriched_report = {
            "metadata": {
                "source_url": url,
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "content_hash": content_hash,
                "author": author
            },
            "threat_classification": classification,
            "indicators_of_compromise": extracted_data,
            "intelligence_assessment": {
                **llm_assessment,
                "trends": trends
            },
            "identity_resolution": alias_data
        }

        # --- SAVE TO OUTPUT FOLDER ---
        filename = f"twip_report_{content_hash[:10]}.json"
        filepath = os.path.join(OUTPUT_DIR, filename)
        
        with open(filepath, 'w') as f:
            json.dump(enriched_report, f, indent=4)
            
        print(f"[SUCCESS] Intelligence package generated: {filename}")
        return jsonify({"status": "success", "file": filename}), 201

    except Exception as e:
        print(f"[ERROR] Pipeline failure: {str(e)}")
        return jsonify({"error": "Internal pipeline processing failed."}), 500

@app.route('/status', methods=['GET'])
def get_status():
    """A quick endpoint for judges to see the pipeline's operational metrics."""
    return jsonify({
        "status": "online",
        "unique_posts_processed": len(seen_hashes),
        "known_threat_actors": len(alias_resolver.known_actors)
    }), 200

if __name__ == '__main__':
    # Run the Flask app on port 5001
    app.run(host='0.0.0.0', port=5001, debug=False)