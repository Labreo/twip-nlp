```markdown
# TWIP: DarkWeb Intelligence Platform - NLP Engine

This repository houses the Natural Language Processing (NLP) and Threat Detection pipeline for TWIP (The DarkWeb Intelligence Platform). It is designed to ingest unstructured, raw HTML/text scraped from I2P hidden services, filter out noise, analyze it for indicators of compromise (IOCs), and output STIX 2.1 compliant intelligence bundles for law enforcement review.

## Architecture Overview

The pipeline operates as a multi-stage machine learning architecture, separated into an automated Pre-Triage ingestion phase and a Deep Analysis Flask webhook API:

1. **Automated Ingestion & Triage (`auto_ingester.py`):** Automatically extracts password-protected ACHE crawler dumps, decodes Base64/deflate streams, enforces context-window length limits, and utilizes Regex/Keyword matching to isolate high-value posts (e.g., crypto wallets, weapon sales) from generic network noise.
2. **Extraction (Regex & NER):** Pulls secure communication IDs (Tox/Jabber), PGP keys, and standard entities using a Transformer-based spaCy model (`en_core_web_trf`).
3. **Classification (Few-Shot Zero-Shot):** Categorizes the text into specific threat domains (e.g., drug sales, weapons, financial fraud) using Hugging Face's `sentence-transformers`.
4. **LLM Analysis (Ollama):** Evaluates the text for urgency, sentiment, imminent physical harm, and newly emerging slang using a locally hosted Llama 3 model.
5. **Alias Resolution:** Cross-references extracted identifiers against a known-actor registry to link disparate usernames algorithmically.
6. **STIX Serialization & Alerting:** Packages the intelligence into STIX 2.1 objects for OpenCTI ingestion and fires real-time Slack webhooks for high-urgency threats.

## Directory Structure

```text
twip-nlp/
├── input/                   # Triage drops clean, high-signal JSON files here
├── output/                  # The pipeline pushes enriched STIX-ready JSON here
│   └── ingested/            # Successfully pushed STIX bundles are archived here
├── pipeline/                # The core logic modules
│   ├── __init__.py
│   ├── auto_ingester.py     # Automated daemon to extract, decode, & filter raw ACHE dumps
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

This pipeline is optimized for a Windows environment (16GB+ RAM recommended) running Python 3.10+, a local instance of Ollama (Llama 3), and a local OpenCTI Docker instance.

### 1. System Dependencies (Crucial)
The `pycti` library requires a C-library to identify file types. 

**Windows:**
You must install the Windows binaries for python-magic:
```bash
pip install python-magic-bin
```
**macOS / Linux (Fallback):**
```bash
brew install libmagic  # macOS
sudo apt-get install libmagic1  # Ubuntu/Debian
```

### 2. Python Environment Setup
Use Conda to isolate the dependencies to prevent conflicts.
```bash
conda create -n twip python=3.10
conda activate twip
pip install -r requirements.txt
```

### 3. Download the NLP Models
Pull the highly accurate spaCy transformer model and the Llama 3 LLM:
```bash
python -m spacy download en_core_web_trf
ollama pull llama3
```

### 4. OpenCTI Docker Setup & Configuration
**Important:** Open Docker Desktop settings, navigate to Resources, and ensure Docker is allocated at least **8GB to 12GB of Memory**.

**A. Clone the repository:**
```bash
git clone [https://github.com/OpenCTI-Platform/docker.git](https://github.com/OpenCTI-Platform/docker.git) opencti-docker
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
CONNECTOR_IMPORT_DOCUMENT_ID=$(uuidgen | tr '[:upper:]' '[:lower:]')
SMTP_HOSTNAME=localhost
ELASTIC_MEMORY_SIZE=4G
EOF
```
*Retrieve your `OPENCTI_ADMIN_TOKEN` from this file for the next step.*

**C. TWIP Project Credentials:**
Create a `.env` file in the root directory of the `twip-nlp` folder:
```env
OPENCTI_URL="http://localhost:8080"
OPENCTI_TOKEN="<insert-token-from-step-B>"
BLOCKCYPHER_TOKEN="<optional-token>"
SLACK_WEBHOOK_URL="<optional-webhook>"
```

---

## Part 2: Instructions to Run

### Step 1: Start Background Services
Open two separate terminals to start the graph database and the local LLM.

**Terminal 1 (OpenCTI):**
```bash
cd opencti-docker
docker compose up -d
```
*(Access the dashboard at `http://localhost:8080` after initialization)*

**Terminal 2 (Ollama):**
```bash
ollama run llama3
```

### Step 2: Start the NLP Orchestrator & Pusher
In a new terminal, start the Flask webhook listener (Port 5001) and the OpenCTI ingestion script.

```bash
conda activate twip
# Terminal 3:
python pipeline/orchestrator.py

# Terminal 4:
python pipeline/opencti_pusher.py
```

### Step 3: Run the Automated Ingestion Daemon
When a new raw ACHE crawler data dump (e.g., password-protected `.7z` archive) is downloaded from the ingestion team, run the auto-ingester. It will automatically detect the archive, extract the contents, decode the Base64 data, filter for high-value targets, and push the clean JSON payloads to the `/input` folder for automated processing:

```bash
conda activate twip
python pipeline/auto_ingester.py
```
*The pipeline will automatically pick up the generated JSONs, analyze them, and push the STIX bundles to OpenCTI.*

---

## Product Vision & Hackathon Roadmap
Beyond the core extraction and mapping pipeline, TWIP aims to implement several advanced capabilities to provide immediate value to Law Enforcement Agencies (LEAs):

* **The Alias Matrix (Cross-Forum De-anonymization):** Leveraging OpenCTI's graph visualization to algorithmically link distinct threat actor aliases across disconnected I2P forums based on shared digital exhaust (PGP keys, Tox IDs, wallet reuse).
* **Zero-Day / Emerging Threat Early Warning Bot:** A real-time webhook integration that monitors the OpenCTI data stream. If a generated STIX `Report` exceeds a high urgency threshold (scored by the LLM) and contains a `Vulnerability` (CVE), it automatically triggers an alert to an LEA Slack or Discord channel.
* **Sector-Based Risk Heatmap:** A visual dashboard (Streamlit/Plotly) that aggregates extracted `Location` and `Target Sector` data to show where Dark Web threat actors are currently focusing their operational planning (e.g., Finance vs. Healthcare).
```