from stix2 import Bundle, Report, ThreatActor, Indicator, Relationship, Identity, Vulnerability, Malware, Tool, Location
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
        
        # Base scraped name
        author_name = metadata.get("author", "Unknown Actor")
        source_url = metadata.get("source_url", "Unknown URL")

        # --- NEW: Extract Alias Resolution Data ---
        alias_data = enriched_data.get("alias_resolution", {})
        is_alias = alias_data.get("alias_detected", False)
        primary_actor_name = alias_data.get("primary_actor", author_name)
        known_aliases = alias_data.get("aliases", [])

        # Ensure the current scraped name is added to the alias list if it differs from the primary
        if is_alias and author_name not in known_aliases and author_name != primary_actor_name:
            known_aliases.append(author_name)

        # 1. Create the Threat Actor
        actor = ThreatActor(
            name=primary_actor_name, # Group under the master name
            aliases=known_aliases,   # Inject all known alter-egos for OpenCTI
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
            
            # STIX 2.1 Standard: Indicator -> indicates -> Threat Actor
            stix_objects.append(Relationship(
                source_ref=ind.id,
                target_ref=actor.id,
                relationship_type="indicates" 
            ))

        # Map Crypto Wallets
        for currency, addresses in iocs.get("wallets", {}).items():
            for addr in addresses:
                _create_indicator(
                    pattern=f"[cryptocurrency:wallet_address = '{addr}']",
                    indicator_type="compromised-infrastructure",
                    desc=f"{currency.capitalize()} Wallet Address"
                )
              
        # Map Tox IDs
        for tox_id in iocs.get("communications", {}).get("tox_id", []):
            _create_indicator(
                pattern=f"[network-traffic:dst_ref.value = '{tox_id}']",
                indicator_type="anonymization",
                desc="Tox Secure Communication ID"
            )

        # --- NEW: MAP VULNERABILITIES, MALWARE, TOOLS, AND LOCATIONS ---
        
        # Map Vulnerabilities (CVEs)
        for cve in iocs.get("cves", []):
            vuln = Vulnerability(name=cve, description=f"Identified zero-day or exploit discussion for {cve}.")
            stix_objects.append(vuln)
            stix_objects.append(Relationship(source_ref=actor.id, target_ref=vuln.id, relationship_type="targets"))

        # Map Malware
        for malware_name in iocs.get("arsenal", {}).get("malware", []):
            mal = Malware(
                name=malware_name.capitalize(), 
                is_family=True,
                description=f"Malware family referenced in intercepted comms."
            )
            stix_objects.append(mal)
            stix_objects.append(Relationship(source_ref=actor.id, target_ref=mal.id, relationship_type="uses"))

        # Map Tools
        for tool_name in iocs.get("arsenal", {}).get("tools", []):
            tool = Tool(
                name=tool_name.title(), 
                description="Exploitation or administration tool."
            )
            stix_objects.append(tool)
            stix_objects.append(Relationship(source_ref=actor.id, target_ref=tool.id, relationship_type="uses"))

        # Map Locations
        for loc_name in iocs.get("locations", []):
            loc = Location(name=loc_name)
            stix_objects.append(loc)
            stix_objects.append(Relationship(source_ref=actor.id, target_ref=loc.id, relationship_type="located-at"))

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
    # Local testing to ensure Aliases and new entities are mapped to STIX JSON correctly
    dummy_payload = {
        "metadata": {
            "source_url": "http://waycuw2c27ruakfblkf5tcegwmt3ot445dlfoypil6bzmm4yxg7a.b32.i2p/thread/104",
            "timestamp": "2026-03-23T10:00:00Z",
            "author": "ShadowBroker"
        },
        "threat_classification": {"top_category": "weapon_sales"},
        "indicators_of_compromise": {
            "wallets": {"bitcoin": ["bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"]},
            "communications": {"tox_id": ["42E9CA1A838AB6CA8E825A7C48B90BAFE1E22B9FA467A7AD4BA2821F1344803BD71BCB00A535"]},
            "cves": ["CVE-2024-3432"],
            "arsenal": {
                "malware": ["lockbit"],
                "tools": ["cobalt strike"]
            },
            "locations": ["London"]
        },
        "intelligence_assessment": {"urgency_score": 9},
        "alias_resolution": {
            "alias_detected": True,
            "primary_actor": "DarkVendor99",
            "aliases": ["ShadowBroker"],
            "confidence_score": 0.7
        }
    }
    
    mapper = STIXMapper()
    stix_json = mapper.generate_bundle(dummy_payload)
    print(stix_json)