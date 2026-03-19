import requests
import time
import json

# The endpoint of your running Orchestrator
API_URL = "http://localhost:5001/ingest"

# Simulated I2P dark web posts
MOCK_PAYLOADS = [
    {
        "url": "http://waycuw2c27ruakfblkf5tcegwmt3ot445dlfoypil6bzmm4yxg7a.b32.i2p/thread/101",
        "author": "ShadowBroker",
        "content": "Need a reliable supplier for 100g of pure coke. Escrow only. BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    },
    {
        "url": "http://hx35bdx7...[snip]...2d.onion/forum/post/442",
        "author": "IronSight",
        "content": "Looking for untraceable ARs. Need it shipped overnight to Chicago, planning something for the rally on Friday."
    },
    {
        "url": "http://waycuw2c27ruakfblkf5tcegwmt3ot445dlfoypil6bzmm4yxg7a.b32.i2p/thread/205",
        "author": "CarderKing",
        "content": "Selling Chase bank logs with email access. $500 balance minimum. Hit me on Tox: 42E9CA1A838AB6CA8E825A7C48B90BAFE1E22B9FA467A7AD4BA2821F1344803BD71BCB00A535"
    },
    {
        # DEDUPLICATION TEST: Exact same content as ShadowBroker's post, but found on a different URL.
        "url": "http://mirror2.waycuw2c27ruakfblkf5tcegwmt3ot445dlfoypil6bzmm4yxg7a.b32.i2p/thread/101",
        "author": "ShadowBroker",
        "content": "Need a reliable supplier for 100g of pure coke. Escrow only. BTC: bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    },
    {
        # ALIAS RESOLUTION TEST: Different author, but shares the same Tox ID as CarderKing.
        "url": "http://anotherforum.b32.i2p/market/view/88",
        "author": "GhostVendor99",
        "content": "Fresh fullz available. High credit score. Contact me on Tox: 42E9CA1A838AB6CA8E825A7C48B90BAFE1E22B9FA467A7AD4BA2821F1344803BD71BCB00A535"
    },
    {
        "url": "http://friendlyforum.b32.i2p/help/1",
        "author": "NewbieUser",
        "content": "Can anyone recommend a good VPN for routing through Tor? I am trying to set up my router."
    }
]

def run_simulation():
    print("Starting TWIP Mock Crawler Simulation...\n")
    
    for i, payload in enumerate(MOCK_PAYLOADS, 1):
        print(f"[*] Crawler found post {i}/{len(MOCK_PAYLOADS)} from author '{payload['author']}'. Sending to pipeline...")
        
        try:
            response = requests.post(
                API_URL, 
                json=payload,
                headers={"Content-Type": "application/json"}
            )
            
            if response.status_code in [200, 201]:
                result = response.json()
                if result.get("status") == "skipped":
                    print("  -> Pipeline response: DEDUPLICATED (Hash already seen).")
                else:
                    print(f"  -> Pipeline response: SUCCESS. Saved as {result.get('file')}")
            else:
                print(f"  -> Pipeline error: {response.status_code} - {response.text}")
                
        except requests.exceptions.ConnectionError:
            print("  -> ERROR: Could not connect to the Orchestrator. Is it running on port 5001?")
            break
            
        # Pause briefly to simulate network travel time and let the LLM breathe
        time.sleep(2)

    print("\nSimulation complete. Check the Orchestrator terminal for deep logs and the /output folder for STIX bundles.")

if __name__ == "__main__":
    run_simulation()