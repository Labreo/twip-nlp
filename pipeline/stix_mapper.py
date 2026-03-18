from stix2 import Bundle, Report, ThreatActor, Indicator, Relationship, Identity
from datetime import datetime
from typing import Dict, Any

class STIXMapper:
    """
    Converts the TWIP enriched intelligence JSON into STIX 2.1 compliant 
    bundles ready for direct OpenCTI ingestion.
    """
    def __init__(self):
        # Create a default identity for the TWIP platform itself
        self.twip_identity = Identity(
            name="TWIP DarkWeb Intelligence Platform",
            identity_class="system",
            description="Automated OSINT and Threat Intelligence Platform"
        )

    def generate_bundle(self, enriched_data: Dict[str, Any]) -> str:
        """
        Takes the output from the Orchestrator and generates a STIX bundle.
        """
        stix_objects = [self.twip_identity]
        metadata = enriched_data.get("metadata", {})
        iocs = enriched_data.get("indicators_of_compromise", {})
        classification = enriched_data.get("threat_classification", {})
        
        author_name = metadata.get("author", "Unknown Actor")
        source_url = metadata.get("source_url", "Unknown URL")

        # 1. Create the Threat Actor
        actor = ThreatActor(
            name=author_name,
            threat_actor_types=["criminal-enterprise" if classification.get("top_category") != "benign" else "unknown"],
            description=f"Automated extraction from I2P hidden service: {source_url}"
        )
        stix_objects.append(actor)

        # 2. Extract Indicators (Wallets, Comms, etc.)
        indicator_objects = []
        
        # Helper to create indicators
        def _create_indicator(pattern: str, indicator_type: str, desc: str):
            ind = Indicator(
                pattern=pattern,
                pattern_type="stix",
                valid_from=datetime.utcnow(),
                indicator_types=[indicator_type],
                description=desc
            )
            stix_objects.append(ind)
            indicator_objects.append(ind)
            # Link the indicator to the actor
            stix_objects.append(Relationship(
                source_ref=actor.id,
                target_ref=ind.id,
                relationship_type="uses"
            ))

        # Map Crypto Wallets
        for currency, addresses in iocs.get("wallets", {}).items():
            for addr in addresses:
                _create_indicator(
                    pattern=f"[cryptocurrency:wallet_address = '{addr}']",
                    indicator_type="compromised-infrastructure", # Close enough STIX mapping
                    desc=f"{currency.capitalize()} Wallet Address"
                )
                
        # Map Tox IDs
        for tox_id in iocs.get("communications", {}).get("tox_id", []):
            _create_indicator(
                pattern=f"[network-traffic:dst_ref.value = '{tox_id}']",
                indicator_type="anonymization",
                desc="Tox Secure Communication ID"
            )

        # 3. Create the Intelligence Report Wrapper
        threat_type = classification.get("top_category", "unknown")
        urgency = enriched_data.get("intelligence_assessment", {}).get("urgency_score", 0)
        
        report = Report(
            name=f"Automated Threat Flag: {threat_type.upper()} [Urgency: {urgency}/10]",
            description=f"Scraped from {source_url}. Analysis flagged this as {threat_type}.",
            published=datetime.utcnow(),
            object_refs=[obj.id for obj in stix_objects if obj.id != self.twip_identity.id],
            created_by_ref=self.twip_identity.id,
            labels=[threat_type, "darkweb", "i2p"]
        )
        stix_objects.append(report)

        # 4. Package everything into a STIX Bundle
        bundle = Bundle(objects=stix_objects)
        return bundle.serialize(indent=4)

if __name__ == "__main__":
    # Local DDIR-style dummy payload test
    dummy_payload = {
        "metadata": {
            "source_url": "http://waycuw2c27ruakfblkf5tcegwmt3ot445dlfoypil6bzmm4yxg7a.b32.i2p/thread/104",
            "timestamp": "2026-03-23T10:00:00Z",
            "author": "ShadowBroker"
        },
        "threat_classification": {"top_category": "drug_sales"},
        "indicators_of_compromise": {
            "wallets": {"bitcoin": ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"]},
            "communications": {"tox_id": ["42E9CA1A838AB6CA8E825A7C48B90BAFE1E22B9FA467A7AD4BA2821F1344803BD71BCB00A535"]}
        },
        "intelligence_assessment": {"urgency_score": 7}
    }
    
    mapper = STIXMapper()
    stix_json = mapper.generate_bundle(dummy_payload)
    print(stix_json)