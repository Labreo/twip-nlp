twip-nlp/
├── input/                   # The crawler drops its raw JSON files here
├── output/                  # The pipeline pushes enriched STIX-ready JSON here
├── pipeline/                # The core logic modules
│   ├── __init__.py
│   ├── extractor.py         # Regex & standard NER (Day 1)
│   ├── classifier.py        # Zero-shot threat categorization (Day 2)
│   ├── stix_mapper.py        # Used to create digestable data for openCTI
│   ├── alias_resolver.py    # Added for clean separation of alias logic
│   ├── llm_analyzer.py      # Ollama integration for sentiment/urgency (Day 3)
│   └── orchestrator.py      # The main execution script tying it all together
├── requirements.txt         # Project dependencies
└── README.md                # Documentation for the judges


conda create -n twip python=3.10
conda activate twip
pip install -r requirements.txt
python -m spacy download en_core_web_trf

Step-by-Step Build Plan (March 18 - March 23)
Date	Component	Tasks
Mar 18	Environment & Extraction	

Initialize requirements.txt. Set up extractor.py with regex for Bitcoin, Monero, and Ethereum addresses. Load a base spaCy model to extract standard entities like phone numbers and usernames.
Mar 19	Threat Classification	

Build classifier.py. Implement classy-classification with Hugging Face zero-shot models. Define your dictionaries for drug sales, weapons, financial fraud, hacking services, and CSAM references.
Mar 20	Local LLM Integration	

Build llm_analyzer.py. Ensure Ollama is running locally. Write strict, structured prompts to evaluate the scraped text for sentiment and urgency scoring to prioritize posts indicating real-world harm.
Mar 21	Trend & Alias Logic	

Expand the LLM prompts to flag newly emerging slang or attack methods. Write logic to compare writing patterns or shared identifiers across posts for your alias resolution requirement.
Mar 22	The Orchestrator	Build orchestrator.py. Tie the modules together. Have it watch an /input folder for the crawler's JSON, run the pipeline, and dump the enriched output to an /output folder. (Wrapping this in a lightweight Flask app could make ingestion super smooth).
Mar 23	Testing & OpenCTI Prep	

Run dummy data (like the DDIR dataset) through the pipeline. Format the final output so it easily maps to STIX-compliant threat objects for your OpenCTI integration.

Requires ollama3 to be running on local machine.