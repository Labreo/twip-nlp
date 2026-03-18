from typing import Dict, List, Any

class AliasResolver:
    """
    Cross-references extracted entities to identify potential links 
    between different usernames across various hidden services.
    """
    def __init__(self):
        # In a production environment, this would be a database query.
        # For the hackathon, we maintain an in-memory threat actor registry.
        self.known_actors = {}

    def calculate_match_score(self, new_data: Dict[str, Any], known_profile: Dict[str, Any]) -> float:
        """
        Calculates a confidence score that two profiles belong to the same actor 
        based on shared hard identifiers.
        """
        score = 0.0
        
        # 1. High-Confidence Match: Cryptographic Keys
        shared_pgp = set(new_data.get("pgp_keys", [])) & set(known_profile.get("pgp_keys", []))
        if shared_pgp:
            score += 0.8  # Almost guaranteed match
            
        # 2. High-Confidence Match: Secure Comms (Tox/Jabber)
        new_comms = []
        for comm_list in new_data.get("communications", {}).values():
            new_comms.extend(comm_list)
            
        known_comms = []
        for comm_list in known_profile.get("communications", {}).values():
            known_comms.extend(comm_list)
            
        if set(new_comms) & set(known_comms):
            score += 0.7
            
        # 3. Medium-Confidence Match: Cryptocurrency Wallets
        new_wallets = []
        for wallet_list in new_data.get("wallets", {}).values():
            new_wallets.extend(wallet_list)
            
        known_wallets = []
        for wallet_list in known_profile.get("wallets", {}).values():
            known_wallets.extend(wallet_list)
            
        if set(new_wallets) & set(known_wallets):
            score += 0.6
            
        return min(score, 1.0) # Cap score at 1.0 (100% confidence)

    def process_and_link(self, username: str, extracted_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests a new profile, checks for aliases, and updates the registry.
        """
        best_match = None
        highest_score = 0.0
        
        # Scan against all known actors
        for known_username, profile in self.known_actors.items():
            if username == known_username:
                continue # Skip self
                
            score = self.calculate_match_score(extracted_data, profile)
            if score > highest_score:
                highest_score = score
                best_match = known_username
                
        # Register the new data
        self.known_actors[username] = extracted_data
        
        # Return resolution results
        if highest_score >= 0.6: # Threshold for an alias match
            return {
                "alias_detected": True,
                "linked_account": best_match,
                "confidence_score": highest_score
            }
        return {"alias_detected": False}

if __name__ == "__main__":
    # Local testing block
    resolver = AliasResolver()
    
    # Profile 1: Extracted from Forum A
    actor_1_data = {
        "communications": {"tox_id": ["42E9CA1A838AB6CA8E825A7C48B90BAFE1E22B9FA467A7AD4BA2821F1344803BD71BCB00A535"]},
        "wallets": {"bitcoin": ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"]}
    }
    resolver.process_and_link("DarkVendor99", actor_1_data)
    
    # Profile 2: Extracted from Forum B
    actor_2_data = {
        "communications": {"tox_id": ["42E9CA1A838AB6CA8E825A7C48B90BAFE1E22B9FA467A7AD4BA2821F1344803BD71BCB00A535"]},
        "wallets": {"monero": ["44AFFq5kSiGBoZ4NMDwYt..."]}
    }
    
    print("Alias Resolution Results:\n" + "="*30)
    result = resolver.process_and_link("ShadowBroker", actor_2_data)
    
    if result["alias_detected"]:
        print(f"ALERT: 'ShadowBroker' is highly likely an alias for '{result['linked_account']}'!")
        print(f"Match Confidence: {result['confidence_score'] * 100}%")