twip-nlp/
├── input/                   # The crawler drops its raw JSON files here
├── output/                  # The pipeline pushes enriched STIX-ready JSON here
├── pipeline/                # The core logic modules
│   ├── __init__.py
│   ├── extractor.py         # Regex & standard NER (Day 1)
│   ├── classifier.py        # Zero-shot threat categorization (Day 2)
│   ├── llm_analyzer.py      # Ollama integration for sentiment/urgency (Day 3)
│   └── orchestrator.py      # The main execution script tying it all together
├── requirements.txt         # Project dependencies
└── README.md                # Documentation for the judges


conda create -n twip python=3.10
conda activate twip
pip install -r requirements.txt
python -m spacy download en_core_web_trf