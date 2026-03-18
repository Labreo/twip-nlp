import json
import requests
from typing import Dict, Any

class ThreatLLMAnalyzer:
    """
    Interfaces with a local Ollama instance to perform advanced 
    sentiment analysis, urgency scoring, and real-world harm evaluation.
    """
    def __init__(self, model_name: str = "llama3", host: str = "http://localhost:11434"):
        self.model_name = model_name
        self.api_url = f"{host}/api/generate"
        
        # The system prompt acts as the strict bounds for the LLM
        self.system_prompt = """
        You are an expert Law Enforcement Cyber Threat Intelligence Analyst. 
        Your job is to read intercepted dark web communications and assess them for 
        urgency, sentiment, and the risk of imminent real-world physical harm.
        
        You MUST respond ONLY with a valid JSON object. Do not include introductory 
        text, markdown blocks, or explanations outside the JSON structure.
        
        Use this exact JSON schema:
        {
            "urgency_score": <int 1-10>,
            "imminent_physical_harm_flag": <boolean>,
            "sentiment": "<string: hostile, transactional, inquiring, or distressed>",
            "reasoning": "<string: a concise, one-sentence justification for the score>"
        }
        """

    def analyze_urgency(self, text: str) -> Dict[str, Any]:
        """
        Sends the scraped text to the local LLM and parses the JSON response.
        """
        prompt = f"{self.system_prompt}\n\nAnalyze the following intercepted communication:\n'{text}'"
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json" # Forces Ollama to constrain output to JSON
        }
        
        try:
            response = requests.post(self.api_url, json=payload, timeout=30)
            response.raise_for_status()
            
            # Extract the response text
            result_text = response.json().get("response", "{}")
            
            # Parse the text into a Python dictionary
            return json.loads(result_text)
            
        except requests.exceptions.ConnectionError:
            print("Error: Could not connect to Ollama. Is it running on localhost:11434?")
            return self._get_fallback_response()
        except json.JSONDecodeError:
            print("Error: The LLM failed to return valid JSON.")
            return self._get_fallback_response()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            return self._get_fallback_response()

    def _get_fallback_response(self) -> Dict[str, Any]:
        """Returns a safe default if the LLM pipeline fails."""
        return {
            "urgency_score": 0,
            "imminent_physical_harm_flag": False,
            "sentiment": "unknown",
            "reasoning": "LLM analysis failed or timed out."
        }
    def detect_trends(self, text: str) -> Dict[str, Any]:
        """
        Scans intercepted text for novel slang, zero-day exploits, or 
        new products not yet in standard threat databases.
        """
        trend_prompt = """
        You are an expert Dark Web Intelligence Analyst. Read the following text and 
        extract any newly emerging slang, novel attack methods, or unknown illicit products.
        If nothing new or unusual is found, return empty lists.
        
        You MUST respond ONLY with a valid JSON object using this exact schema:
        {
            "novel_slang": ["<string>", "<string>"],
            "new_attack_methods": ["<string>"],
            "unrecognized_products": ["<string>"]
        }
        """
        
        prompt = f"{trend_prompt}\n\nAnalyze this text:\n'{text}'"
        
        payload = {
            "model": self.model_name,
            "prompt": prompt,
            "stream": False,
            "format": "json"
        }
        
        try:
            response = requests.post(self.api_url, json=payload, timeout=30)
            response.raise_for_status()
            return json.loads(response.json().get("response", "{}"))
        except Exception as e:
            print(f"Trend extraction failed: {e}")
            return {"novel_slang": [], "new_attack_methods": [], "unrecognized_products": []}

if __name__ == "__main__":
    # Local testing block
    analyzer = ThreatLLMAnalyzer()
    
    # Testing two very different scenarios
    sample_posts = [
        "Need a reliable vendor for bulk CCs. Doing a massive cashout next week.",
        "Looking for an untraceable piece. Need it shipped overnight to Chicago, planning something for the rally on Friday. Escrow only."
    ]
    
    print("LLM Urgency & Sentiment Analysis:\n" + "="*40)
    for post in sample_posts:
        print(f"\nIntercepted Text: '{post}'")
        analysis = analyzer.analyze_urgency(post)
        
        for key, value in analysis.items():
            print(f"  - {key}: {value}")