import os
import json
import hashlib
import time
import requests
from datetime import datetime
from flask import Flask, request, jsonify
from dotenv import load_dotenv

from stix_mapper import STIXMapper
from extractor import DarkWebExtractor
from llm_analyzer import ThreatLLMAnalyzer
from alias_resolver import AliasResolver

# NOTE: ThreatClassifier intentionally removed — category comes from
# pre_analysis_metadata injected by auto_ingester.py, avoiding a
# PyTorch memory clash between two transformer models in the same process.

load_dotenv()
SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

app = Flask(__name__)

# ==========================================
# 1. Initialize Pipeline (Loads Models Once)
# ==========================================
print("Initializing TWIP AI Pipeline... (This may take a minute)")
extractor = DarkWebExtractor()
llm_analyzer = ThreatLLMAnalyzer()
stix_mapper = STIXMapper()
alias_resolver = AliasResolver()

seen_hashes = set()

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUTPUT_DIR = os.path.join(BASE_DIR, 'output')
os.makedirs(OUTPUT_DIR, exist_ok=True)

# Maps auto_ingester categories → STIX/pipeline categories
CATEGORY_MAP = {
    "weapons":        "weapons",
    "drugs":          "drug_sales",
    "cybercrime":     "hacking_services",
    "financial_fraud":"financial_fraud",
    "exploitation":   "hacking_services",
    "csam_references":"csam_references",
    "crypto_only":    "financial_fraud",  # crypto-only defaults to fraud
}

# ==========================================
# SLACK ALERT LOGIC
# ==========================================
def send_slack_alert(author: str, urgency: int, category: str,
                     content: str, wallets: list):
    if not SLACK_WEBHOOK_URL:
        print("[-] Skipping Slack Alert: No Webhook URL configured.")
        return

    wallet_str = "\n".join(wallets) if wallets else "None detected."
    color = "#FF0000" if urgency >= 9 else "#FFA500"
    ticks = chr(96) * 3

    payload = {
        "attachments": [{
            "fallback": f"HIGH URGENCY THREAT: [{urgency}/10] {category}",
            "color": color,
            "title": f"🚨 HIGH URGENCY THREAT DETECTED: [{urgency}/10]",
            "text": f"*{category}* threat detected by TWIP Pipeline.",
            "fields": [
                {"title": "Actor/Alias",       "value": author,               "short": True},
                {"title": "Threat Category",   "value": category,             "short": True},
                {"title": "Intercepted Comm",  "value": f"> {content[:200]}...","short": False},
                {"title": "Extracted Wallets", "value": f"{ticks}\n{wallet_str}\n{ticks}", "short": False}
            ],
            "footer": "TWIP Automated OSINT Pipeline • Pushed to OpenCTI",
            "ts": int(time.time())
        }]
    }
    try:
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=3)
        print("[+] Slack Alert Fired Successfully.")
    except Exception as e:
        print(f"[-] Failed to fire Slack alert: {e}")


# ==========================================
# 2. The Core Processing Logic
# ==========================================
def generate_content_hash(text: str) -> str:
    return hashlib.sha256(text.encode('utf-8')).hexdigest()


@app.route('/ingest', methods=['POST'])
def ingest_data():
    try:
        data = request.get_json()
        if not data or 'content' not in data:
            return jsonify({"error": "Invalid payload. 'content' field required."}), 400

        url     = data.get('url', 'unknown_source')
        content = data['content']
        author  = data.get('author', 'anonymous')

        # --- DEDUPLICATION ---
        content_hash = generate_content_hash(content)
        if content_hash in seen_hashes:
            print(f"[-] Duplicate skipped from: {url}")
            return jsonify({"status": "skipped", "reason": "duplicate"}), 200

        seen_hashes.add(content_hash)
        print(f"[+] Processing new intelligence from: {url}")

        # --- STAGE 1: Extract IOCs (always runs, fast regex) ---
        extracted_data = extractor.process_text(content)

        # --- STAGE 2: Category from pre_analysis_metadata ---
        # auto_ingester.py already classified this via the scored keyword filter.
        # Using that ground truth avoids loading a second transformer model,
        # which caused PyTorch memory clashes on Apple Silicon.
        pre_metadata = data.get("pre_analysis_metadata", {})
        raw_category = pre_metadata.get("primary_category", "unknown")
        top_category = CATEGORY_MAP.get(raw_category, "benign")

        classification = {
            "top_category": top_category,
            "confidence": 0.99,  # pre-filter is high-precision by design
            "method": "heuristic_pre_filter"
        }

        # --- STAGE 3: Gate Ollama ---
        # If it passed the pre-filter, it's almost certainly a threat.
        # Only skip Ollama for the rare benign fallback.
        llm_assessment = {
            "urgency_score": 0,
            "sentiment": "neutral",
            "summary": "Ollama skipped — post classified as non-threatening."
        }
        trends = []
        ollama_ran = False

        if top_category != "benign":
            print(f"[*] Running LLM analysis for {top_category}...")
            llm_assessment = llm_analyzer.analyze_urgency(content)
            trends = llm_analyzer.detect_trends(content)
            ollama_ran = True
        else:
            print(f"[~] Ollama skipped — benign fallback")

        # --- STAGE 4: Alias Resolution ---
        alias_data = alias_resolver.process_and_link(author, extracted_data)

        # --- STAGE 5: Slack Alert for High Urgency ---
        urgency_score = int(llm_assessment.get("urgency_score", 0))
        if urgency_score >= 8 and top_category != "benign":
            all_wallets = []
            for currency, addrs in extracted_data.get("wallets", {}).items():
                all_wallets.extend(addrs)
            send_slack_alert(author, urgency_score, top_category,
                             content, all_wallets)

        # --- COMPILE ENRICHED REPORT ---
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
                "trends": trends,
                "ollama_ran": bool(ollama_ran)
            },
            "alias_resolution": alias_data
        }

        # --- COMPILE & SAVE STIX BUNDLE ---
        stix_bundle_json = stix_mapper.generate_bundle(enriched_report)

        filename = f"stix_bundle_{content_hash[:10]}.json"
        filepath = os.path.join(OUTPUT_DIR, filename)

        with open(filepath, 'w') as f:
            f.write(stix_bundle_json)

        print(f"[SUCCESS] STIX bundle generated: {filename} "
              f"| Category: {top_category} "
              f"| Urgency: {urgency_score}/10")

        return jsonify({
            "status": "success",
            "file": filename,
            "category": top_category,
            "urgency": urgency_score,
            "ollama_ran": bool(ollama_ran)
        }), 201

    except Exception as e:
        print(f"[ERROR] Pipeline failure: {str(e)}")
        return jsonify({"error": "Internal pipeline processing failed."}), 500


@app.route('/status', methods=['GET'])
def get_status():
    output_files = len([
        f for f in os.listdir(OUTPUT_DIR)
        if f.startswith("stix_bundle_")
    ])
    return jsonify({
        "status": "🟢 ONLINE",
        "platform": "TWIP — Dark Web Intelligence Platform",
        "stats": {
            "unique_posts_processed": len(seen_hashes),
            "known_threat_actors": len(alias_resolver.known_actors),
            "stix_bundles_generated": output_files,
        },
        "modules": {
            "extractor":      "✅ online",
            "classifier":     "✅ online (heuristic bypass — memory optimized)",
            "llm_analyzer":   "✅ online (gated)",
            "alias_resolver": "✅ online",
            "stix_mapper":    "✅ online"
        },
        "llm_gate": {
            "skip_categories": ["benign"],
            "description": "Ollama runs on all pre-filter confirmed threats"
        },
        "network": "I2P",
        "llm_backend": "Ollama (local — zero cloud egress)"
    }), 200


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=False)