
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
├── .env.sample              # Project environment sample
├── mock_crawler.py          # Built for end-to-end pipeline testing 
├── requirements.txt         # Project dependencies
└── README.md                # Project documentation
```

---

## Part 1: Prerequisites & Setup

This pipeline requires Python 3.10+, a local instance of Ollama running a compatible LLM (e.g., Llama 3), and a locally running OpenCTI instance via Docker. 

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

### 2. Python Environment Setup
It is highly recommended to use Conda to isolate the Python dependencies. 

```bash
conda create -n twip python=3.10
conda activate twip
pip install -r requirements.txt
```

### 3. Download the NLP Models
Pull the highly accurate spaCy transformer model required by the `extractor.py` module:

```bash
python -m spacy download en_core_web_trf
```
Ensure you also have Ollama installed on your system and download the Llama 3 model:
```bash
ollama pull llama3
```

### 4. OpenCTI Docker Setup & Configuration
TWIP pushes intelligence directly into an OpenCTI instance. **Important:** Open Docker Desktop settings, navigate to Resources, and ensure Docker is allocated at least **8GB to 12GB of Memory**.

**A. Clone the repository:**
```bash
git clone [https://github.com/OpenCTI-Platform/docker.git](https://github.com/OpenCTI-Platform/docker.git) opencti-docker
cd opencti-docker
```

**B. Generate the `.env` configuration:**
Run this command inside the `opencti-docker` folder to instantly generate secure UUIDs and configuration parameters:
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
CONNECTOR_IMPORT_DOCUMENT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
SMTP_HOSTNAME=localhost
ELASTIC_MEMORY_SIZE=4G
EOF
```
*Run `grep OPENCTI_ADMIN_TOKEN .env` to retrieve the generated UUID. You will need this for the TWIP `.env` file.*

**C. Apple Silicon (M-Series) Fix:**
If running on an Apple Silicon Mac, edit the `docker-compose.yml` file and add `platform: linux/amd64` to all connector services (e.g., `connector-export-file-stix`, `connector-import-document`, `xtm-composer`) to force Rosetta 2 emulation.

**D. TWIP Project Credentials:**
Create a `.env` file in the root directory of the `twip-nlp` folder and add your credentials:
```env
OPENCTI_URL="http://localhost:8080"
OPENCTI_TOKEN="<insert-token-from-step-B>"
BLOCKCYPHER_TOKEN="<optional-token>"
SLACK_WEBHOOK_URL="<optional-webhook>"
```

---

## Part 2: Instructions to Run

To run the pipeline end-to-end, you need to spin up the background services and then start the Flask orchestrator.

### Step 1: Start Background Services
Open two separate terminal windows to start your database and your local LLM.

**Terminal 1 (OpenCTI):**
```bash
cd opencti-docker
docker compose up -d rsa-key-generator redis elasticsearch minio rabbitmq xtm-composer opencti worker
```
*(Wait 2-3 minutes for initialization, then access the dashboard at `http://localhost:8080`)*

**Terminal 2 (Ollama):**
```bash
ollama run llama3
```

### Step 2: Start the Orchestrator
In a new terminal window, activate your environment and start the Flask webhook listener on port `5001`.

```bash
conda activate twip
python pipeline/orchestrator.py
```

### Step 3: Start the OpenCTI Pusher Daemon
In another terminal, run the pusher script. This script will continuously watch the `/output` folder and automatically ingest newly generated STIX bundles into OpenCTI.

```bash
conda activate twip
python pipeline/opencti_pusher.py
```

### Step 4: Ingest Data

**Option A: Automated Batch Ingestion (End-to-End Test)**
To simulate a live data feed from I2P forums, ensure your mock dataset is saved at `input/all_posts.json` and run the mock crawler in a new terminal:
```bash
conda activate twip
python mock_crawler.py
```

**Option B: Manual Ingestion (Single Post)**
You can push data to the `/ingest` endpoint manually via a `POST` request.
```bash
curl -X POST http://localhost:5001/ingest \
-H "Content-Type: application/json" \
-d '{
    "url": "http://example.b32.i2p/thread/104",
    "author": "ShadowBroker",
    "content": "Need a reliable supplier for 100g of pure coke. Escrow only. Hit me on tox: 42E9CA1A838AB6CA8E825A7C48B90BAFE1E22B9FA467A7AD4BA2821F1344803BD71BCB00A535"
}'
```

---

## Product Vision & Hackathon Roadmap
Beyond the core extraction and mapping pipeline, TWIP aims to implement several advanced capabilities to provide immediate value to Law Enforcement Agencies (LEAs):

* **The Alias Matrix (Cross-Forum De-anonymization):** Leveraging OpenCTI's graph visualization to algorithmically link distinct threat actor aliases across disconnected I2P forums based on shared digital exhaust (PGP keys, Tox IDs, wallet reuse).
* **Zero-Day / Emerging Threat Early Warning Bot:** A real-time webhook integration that monitors the OpenCTI data stream. If a generated STIX `Report` exceeds a high urgency threshold (scored by the LLM) and contains a `Vulnerability` (CVE), it automatically triggers an alert to an LEA Slack or Discord channel.
* **Sector-Based Risk Heatmap:** A visual dashboard (Streamlit/Plotly) that aggregates extracted `Location` and `Target Sector` data to show where Dark Web threat actors are currently focusing their operational planning (e.g., Finance vs. Healthcare).
```