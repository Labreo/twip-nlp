***

```markdown
# TWIP: DarkWeb Intelligence Platform - NLP Engine

This repository houses the Natural Language Processing (NLP) and Threat Detection pipeline for TWIP (The DarkWeb Intelligence Platform). It is designed to ingest unstructured, raw HTML/text scraped from I2P hidden services, analyze it for indicators of compromise (IOCs) and physical threats, and output STIX 2.1 compliant intelligence bundles for law enforcement review.

## Architecture Overview

The pipeline operates as a lightweight Flask webhook API. It receives scraped forum data, hashes it for deduplication, and passes it through a multi-stage machine learning architecture:

1. **Extraction (Regex & NER):** Pulls cryptocurrency wallets, secure communication IDs (Tox/Jabber), PGP keys, and standard entities using a Transformer-based spaCy model (`en_core_web_trf`).
2. **Classification (Few-Shot Zero-Shot):** Categorizes the text into specific threat domains (e.g., drug sales, weapons, financial fraud) using Hugging Face's `sentence-transformers`.
3. **LLM Analysis (Ollama):** Evaluates the text for urgency, sentiment, imminent physical harm, and newly emerging slang using a locally hosted Llama 3 model.
4. **Alias Resolution:** Cross-references extracted identifiers against a known-actor registry to link disparate usernames.
5. **STIX Serialization:** Packages the enriched intelligence into STIX 2.1 objects ready for ingestion by OpenCTI.

## Directory Structure

```text
twip-nlp/
├── input/                   # The crawler drops its raw JSON files here
├── output/                  # The pipeline pushes enriched STIX-ready JSON here
│   └── ingested/            # Successfully pushed STIX bundles are archived here
├── pipeline/                # The core logic modules
│   ├── __init__.py
│   ├── extractor.py         # Regex & standard NER 
│   ├── classifier.py        # Zero-shot threat categorization 
│   ├── stix_mapper.py       # Converts enriched data into STIX 2.1 bundles
│   ├── alias_resolver.py    # Cross-forum threat actor linking logic
│   ├── llm_analyzer.py      # Ollama integration for sentiment/urgency 
│   ├── opencti_pusher.py    # Automated script to push STIX bundles to OpenCTI
│   └── orchestrator.py      # The Flask API and main execution script 
├── .env.sample             # Project environment sample
├── mock_crawler.py          # Built for testing purposes
├── requirements.txt         # Project dependencies
└── README.md                # Project documentation
```

## Prerequisites & Installation

This pipeline requires Python 3.10+, a local instance of Ollama running a compatible LLM (e.g., Llama 3), and a running OpenCTI instance.

### 1. System Dependencies (Crucial)
The `pycti` library requires the system-level C-library `libmagic` to identify file types. You must install this before installing the Python requirements.

**macOS (Homebrew):**
```bash
brew install libmagic
```
**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install libmagic1
```

### 2. Environment Setup
It is highly recommended to use Conda to isolate the Python dependencies. 

```bash
conda create -n twip python=3.10
conda activate twip
pip install -r requirements.txt
```

### 3. Download the Transformer Model
Pull the highly accurate spaCy transformer model required by the `extractor.py` module:

```bash
python -m spacy download en_core_web_trf
```

### 4. Start the Local LLM Server
The `llm_analyzer.py` module relies on a local Ollama server to process urgency and sentiment without sending sensitive data to the cloud. Open a separate terminal window and run:

```bash
ollama run llama3
```
*(Leave this terminal open and running in the background).*

## Running the Pipeline

Start the Orchestrator, which initializes the machine learning models into memory and starts the Flask webhook listener on port `5001`.

```bash
conda activate twip
python pipeline/orchestrator.py
```

### Interacting with the API

**Ingest Data:**
The crawling engine pushes data to the `/ingest` endpoint via a POST request.

```bash
curl -X POST http://localhost:5001/ingest \
-H "Content-Type: application/json" \
-d '{
    "url": "http://example.b32.i2p/thread/104",
    "author": "ShadowBroker",
    "content": "Need a reliable supplier for 100g of pure coke. Escrow only. Hit me on tox: 42E9CA1A838AB6CA8E825A7C48B90BAFE1E22B9FA467A7AD4BA2821F1344803BD71BCB00A535"
}'
```
*Successful ingestion will output a STIX 2.1 `.json` bundle into the `/output` directory.*

**Check Status:**
Verify the pipeline's operational metrics via a GET request in your browser or terminal.
```bash
curl http://localhost:5001/status
```

### Pushing to OpenCTI
Once STIX bundles are generated in the `/output` directory, you can push them directly to your local OpenCTI knowledge graph. 

1. Ensure your OpenCTI Docker instance is running.
2. Create a `.env` file in the root directory (`twip-nlp/.env`) and add your OpenCTI credentials:
   ```env
   OPENCTI_URL="http://localhost:8080"
   OPENCTI_TOKEN="your-uuid-token-here"
   ```
3. Run the pusher script:
   ```bash
   python pipeline/opencti_pusher.py
   ```
*Note: Successfully ingested JSON files are automatically moved to `/output/ingested/` to prevent duplicate uploads during subsequent runs.*

## Module Breakdown

* **`extractor.py`**: Handles static pattern matching. Uses comprehensive regex to catch modern crypto wallets (P2PKH, P2SH, Bech32, Monero subaddresses) and secure communication channels.
* **`classifier.py`**: Uses `classy-classification` combined with Hugging Face zero-shot models to semantically map unstructured text to predefined threat dictionaries.
* **`llm_analyzer.py`**: Interfaces strictly with Ollama's JSON-mode API to guarantee machine-readable sentiment, urgency scoring, and trend detection without hallucination.
* **`alias_resolver.py`**: An algorithmic matching engine that calculates confidence scores to link separate profiles sharing hard cryptographic identifiers. 
* **`stix_mapper.py`**: Wraps the final intelligence dictionary into OpenCTI-compatible `Report`, `ThreatActor`, and `Indicator` objects, strictly adhering to STIX 2.1 relationship ontology (e.g., `Indicator -> indicates -> ThreatActor`).
* **`opencti_pusher.py`**: The delivery mechanism. Uses the `pycti` client to read generated STIX bundles, parse them from JSON, and ingest them directly into the OpenCTI graph database. Safely archives files post-ingestion.
* **`orchestrator.py`**: The central nervous system. It manages model loading, payload deduplication (via SHA-256 hashing), and directs the data flow through the pipeline.

## Product Vision & Hackathon Roadmap
Beyond the core extraction and mapping pipeline, TWIP aims to implement several advanced capabilities to provide immediate value to Law Enforcement Agencies (LEAs):

* **The Alias Matrix (Cross-Forum De-anonymization):** Leveraging OpenCTI's graph visualization to algorithmically link distinct threat actor aliases across disconnected I2P forums based on shared digital exhaust (PGP keys, Tox IDs, wallet reuse).
* **Zero-Day / Emerging Threat Early Warning Bot:** A real-time webhook integration that monitors the OpenCTI data stream. If a generated STIX `Report` exceeds a high urgency threshold (scored by the LLM) and contains a `Vulnerability` (CVE), it automatically triggers an alert to an LEA Slack or Discord channel.
* **Sector-Based Risk Heatmap:** A visual dashboard (Streamlit/Plotly) that aggregates extracted `Location` and `Target Sector` data to show where Dark Web threat actors are currently focusing their operational planning (e.g., Finance vs. Healthcare).
```

***

