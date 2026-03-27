# TWIP: DarkWeb Intelligence Platform - NLP Engine

This repository houses the Natural Language Processing (NLP) and Threat Detection pipeline for TWIP (The DarkWeb Intelligence Platform). It is designed to ingest unstructured, raw HTML/text scraped from I2P hidden services, filter out noise, analyze it for indicators of compromise (IOCs), and output STIX 2.1 compliant intelligence bundles for law enforcement review.

## Architecture Overview

The pipeline operates as a multi-stage machine learning architecture, separated into an automated Pre-Triage ingestion phase and a Deep Analysis Flask webhook API:

1. **Automated Ingestion & Triage (`auto_ingester.py`):** Automatically extracts password-protected ACHE crawler dumps, decodes Base64/deflate streams, enforces context-window length limits, and utilizes a **Scoring-Based Threat Filter** to isolate high-value posts (e.g., crypto wallets, weapon sales) from generic network noise. After successful processing, the source archive is automatically moved to the OS trash bin.
2. **Input Pusher (`input_pusher.py`):** Reads every filtered JSON file from `/input`, sorts them by threat score (highest first), and posts them sequentially to the Flask orchestrator. Replaces the need to manually feed data after triage.
3. **Extraction (Regex & NER):** Pulls cryptocurrency wallets, secure communication IDs (Tox/Jabber), PGP keys, CVE references, and standard entities using a Transformer-based spaCy model (`en_core_web_trf`).
4. **Classification (Few-Shot Zero-Shot):** Categorizes the text into specific threat domains (e.g., drug sales, weapons, financial fraud) using Hugging Face's `sentence-transformers`.
5. **LLM Gatekeeper & Analysis (Ollama):** To optimize local compute resources, the pipeline bypasses heavy LLM processing for benign or low-confidence posts. For verified threats (confidence ≥ 0.45, category ≠ benign), it evaluates urgency, sentiment, imminent physical harm, and emerging slang using a locally hosted Llama 3 model.
6. **Alias Resolution:** Cross-references extracted identifiers against a persistent known-actor registry (`data/actor_registry.json`) to link disparate usernames algorithmically.
7. **STIX Serialization & Alerting:** Packages the intelligence into STIX 2.1 objects for OpenCTI ingestion and fires real-time Slack webhooks for high-urgency threats (score ≥ 8/10).

## Directory Structure

```text
twip-nlp/
├── input/                   # Triage drops clean, high-signal JSON files here
├── output/                  # The pipeline pushes enriched STIX-ready JSON here
│   └── ingested/            # Successfully pushed STIX bundles are archived here
├── data/
│   └── actor_registry.json  # Persistent alias resolver state (auto-generated)
├── pipeline/                # The core logic modules
│   ├── __init__.py
│   ├── auto_ingester.py     # Extracts, decodes, scores & filters raw ACHE dumps → moves archive to trash
│   ├── extractor.py         # Regex & standard NER
│   ├── classifier.py        # Zero-shot threat categorization
│   ├── stix_mapper.py       # Converts enriched data into STIX 2.1 bundles
│   ├── alias_resolver.py    # Cross-forum threat actor linking with persistent registry
│   ├── llm_analyzer.py      # Ollama integration for sentiment/urgency (gated)
│   ├── opencti_pusher.py    # Daemon: watches output/ and auto-pushes bundles to OpenCTI
│   └── orchestrator.py      # Flask API, deduplication, LLM gate, Slack alerts
├── test/                    # Contains mock data for offline demo resilience
│   └── all_posts.json       # Simulated I2P data feed with interconnected threat actors
├── .env.sample              # Project environment sample
├── input_pusher.py          # Pushes all files from /input to the orchestrator (sorted by threat score)
├── mock_crawler.py          # Feeds test/all_posts.json into the pipeline for demo simulation
├── requirements.txt         # Project dependencies
└── README.md                # Project documentation
```

---

## Part 1: Prerequisites & Setup

This pipeline is optimized for a Windows environment (16GB+ RAM recommended) running Python 3.10+, a local instance of Ollama (Llama 3), and a local OpenCTI Docker instance.

### 1. System Dependencies (Crucial)

The `pycti` library requires a C-library to identify file types. Install `send2trash` to enable safe archive deletion to the OS trash bin after processing.

**Windows:**
```bash
pip install python-magic-bin send2trash
```

**macOS / Linux (Fallback):**
```bash
brew install libmagic        # macOS
sudo apt-get install libmagic1  # Ubuntu/Debian
pip install send2trash
```

### 2. Python Environment Setup

Use Conda to isolate the dependencies and prevent conflicts.

```bash
conda create -n twip python=3.10
conda activate twip
pip install -r requirements.txt
```

### 3. Download the NLP Models

Pull the spaCy transformer model and the Llama 3 LLM:

```bash
python -m spacy download en_core_web_trf
ollama pull llama3
```

### 4. OpenCTI Docker Setup & Configuration

**Important:** Open Docker Desktop → Resources and allocate at least **8GB to 12GB of Memory**. Insufficient RAM will cause Elasticsearch or RabbitMQ to crash on startup.

**A. Clone the OpenCTI Docker repository:**
```bash
git clone https://github.com/OpenCTI-Platform/docker.git opencti-docker
cd opencti-docker
```

**B. Generate the `.env` configuration:**
Run this in a Git Bash or WSL terminal to generate secure UUIDs:
```bash
cat << EOF > .env
OPENCTI_ADMIN_EMAIL=admin@twip.local
OPENCTI_ADMIN_PASSWORD=HackathonWinner2026!
OPENCTI_ADMIN_TOKEN=$(uuidgen | tr '[:upper:]' '[:lower:]')
OPENCTI_BASE_URL=http://localhost:8080
MINIO_ROOT_USER=$(uuidgen | tr '[:upper:]' '[:lower:]')
MINIO_ROOT_PASSWORD=$(uuidgen | tr '[:upper:]' '[:lower:]')
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
CONNECTOR_HISTORY_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
CONNECTOR_EXPORT_FILE_STIX_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
CONNECTOR_EXPORT_FILE_CSV_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
CONNECTOR_EXPORT_FILE_TXT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
CONNECTOR_IMPORT_FILE_STIX_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
CONNECTOR_IMPORT_DOCUMENT_ID=$(uuidgen | tr '[:upper:]' '[:lower']')
SMTP_HOSTNAME=localhost
ELASTIC_MEMORY_SIZE=4G
EOF
```
*Run `grep OPENCTI_ADMIN_TOKEN .env` to retrieve the generated token for the next step.*

**C. TWIP Project Credentials:**
Create a `.env` file in the root of the `twip-nlp` folder:
```env
OPENCTI_URL="http://localhost:8080"
OPENCTI_TOKEN="<insert-token-from-step-B>"
BLOCKCYPHER_TOKEN="<optional-token>"
SLACK_WEBHOOK_URL="<optional-slack-webhook>"
```

---

## Part 2: Instructions to Run

### Step 1: Start Background Services

Open two separate terminals.

**Terminal 1 — OpenCTI:**
```bash
cd opencti-docker
docker compose up -d
```
*(Wait 2–3 minutes, then access the dashboard at `http://localhost:8080`)*

**Terminal 2 — Ollama LLM:**
```bash
ollama run llama3
```
*(Leave this running in the background)*

### Step 2: Start the NLP Orchestrator & OpenCTI Pusher

**Terminal 3 — Flask API (port 5001):**
```bash
conda activate twip
python pipeline/orchestrator.py
```

**Terminal 4 — OpenCTI Pusher Daemon:**
```bash
conda activate twip
python pipeline/opencti_pusher.py
```
*This daemon watches `/output` every 10 seconds and automatically pushes new STIX bundles to OpenCTI.*

### Step 3: Live Data — Process a Real ACHE Crawler Dump

When the crawling team delivers a new password-protected `.7z` archive to your `Downloads/` folder:

**Step 3a — Triage and filter the raw dump:**
```bash
conda activate twip
python pipeline/auto_ingester.py
```
This will extract and decode the archive, score every post, write high-signal files to `/input` sorted by threat score, and **move the source archive to your OS trash bin** automatically.

**Step 3b — Push filtered posts to the pipeline:**
```bash
conda activate twip
python input_pusher.py
```
This reads every JSON file from `/input`, processes them highest-threat-score first, and sends each post to the Flask orchestrator. Terminal output shows category and urgency score per post in real time:
```
[1/150] hit_cybercrime_009pts_...
  -> ✓ stix_bundle_8c40f9... | cybercrime | urgency 8/10 | LLM✓
[2/150] hit_financial_fraud_006pts_...
  -> ✓ stix_bundle_3d9a87... | financial_fraud | urgency 3/10 | LLM✓
[3/150] hit_drugs_003pts_...
  -> ✓ stix_bundle_eb6d47... | drug_sales | urgency 0/10 | LLM skipped
```

### Step 4: Demo / Offline Simulation

To simulate a live I2P data feed without waiting for the crawler — ideal for presentations:

```bash
conda activate twip
python mock_crawler.py
```
*Reads `test/all_posts.json` (40 interconnected mock posts) and feeds them directly into the orchestrator.*

### Step 5: Check Pipeline Status

At any time, verify operational metrics:
```bash
curl http://localhost:5001/status
```

---

## Module Breakdown

| Module | Role |
|---|---|
| `auto_ingester.py` | Scores and filters raw ACHE crawler dumps. Moves source archive to trash on completion. |
| `input_pusher.py` | Reads `/input` files sorted by threat score and POSTs each to the Flask orchestrator. |
| `extractor.py` | Regex extraction of crypto wallets, Tox IDs, PGP keys, CVEs, phone numbers. |
| `classifier.py` | Few-shot zero-shot classification into threat domains using sentence-transformers. |
| `llm_analyzer.py` | Ollama LLM for urgency scoring and trend detection. Only runs on confirmed threats. |
| `alias_resolver.py` | Matches actors sharing hard identifiers (PGP, Tox ID, wallets). Persists to `data/actor_registry.json`. |
| `stix_mapper.py` | Maps enriched reports to STIX 2.1 objects: ThreatActor, Indicator, Malware, Tool, Vulnerability, Location, Report. |
| `opencti_pusher.py` | Daemon that polls `/output` every 10s and ingests new STIX bundles into OpenCTI via pycti. |
| `orchestrator.py` | Flask API. Deduplication, LLM gate (skips Ollama for benign/low-confidence), Slack alerts for urgency ≥ 8. |

---

## Product Vision & Hackathon Roadmap

Beyond the core pipeline, TWIP aims to implement:

- **Sector-Based Risk Heatmap:** Streamlit/Plotly dashboard aggregating extracted `Location` and `Target Sector` data to visualize where Dark Web threat actors are focusing operational planning.
- **Zero-Day Early Warning:** Real-time webhook that monitors the OpenCTI data stream and pages a Slack channel when a STIX Report exceeds urgency threshold and contains a `Vulnerability` (CVE).
- **Portable Deployment:** Single `docker-compose.yml` spinning up OpenCTI, the Flask pipeline, and the OpenCTI pusher daemon together for one-command LEA deployment.
