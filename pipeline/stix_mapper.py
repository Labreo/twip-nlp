import uuid
from urllib.parse import urlparse
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
        """Takes the output from the Orchestrator and generates a STIX bundle."""
        stix_objects = [self.twip_identity]
        metadata = enriched_data.get("metadata", {})
        iocs = enriched_data.get("indicators_of_compromise", {})
        classification = enriched_data.get("threat_classification", {})
        
        author_name = metadata.get("author", "Unknown_I2P_Actor")
        source_url = metadata.get("source_url", "Unknown URL")
        
        # --- NEW: Extract Raw Text for the Report Description ---
        raw_text = metadata.get("raw_text", "No raw text provided in payload.")

        # --- Deterministic Actor ID Generation ---
        # If the author is unknown, use the site's domain as their name
        if author_name in ["Unknown_I2P_Actor", "anonymous", "Unknown Actor"]:
            domain = urlparse(source_url).netloc if source_url != "Unknown URL" else "unknown_domain"
            actor_name = f"Unknown Actor ({domain})"
        else:
            actor_name = author_name

        alias_data = enriched_data.get("alias_resolution", {})
        is_alias = alias_data.get("alias_detected", False)
        
        # Override with primary alias if found
        primary_actor_name = alias_data.get("primary_actor", actor_name)
        if primary_actor_name in ["Unknown_I2P_Actor", "anonymous", "Unknown Actor"]:
            domain = urlparse(source_url).netloc if source_url != "Unknown URL" else "unknown_domain"
            primary_actor_name = f"Unknown Actor ({domain})"

        known_aliases = alias_data.get("aliases", [])
        if is_alias and actor_name not in known_aliases and actor_name != primary_actor_name:
            known_aliases.append(actor_name)

        # Generate a deterministic UUIDv5 based on the primary actor name
        # This guarantees OpenCTI merges actors with the exact same name
        deterministic_actor_id = f"threat-actor--{uuid.uuid5(uuid.NAMESPACE_URL, primary_actor_name)}"

        # 1. Create the Threat Actor
        actor = ThreatActor(
            id=deterministic_actor_id,
            name=primary_actor_name,
            aliases=known_aliases,
            threat_actor_types=["criminal-enterprise" if classification.get("top_category") != "benign" else "unknown"],
            description=f"Automated extraction from I2P hidden service: {source_url}"
        )
        stix_objects.append(actor)

        # 2. Extract Indicators (Wallets, Comms, etc.)
        indicator_objects = []
        
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

        # 3. Create the Intelligence Report Wrapper
        threat_type = classification.get("top_category", "unknown")
        urgency = enriched_data.get("intelligence_assessment", {}).get("urgency_score", 0)
        
        # --- NEW: Formatted Description ---
        formatted_description = (
            f"**Source:** {source_url}\n\n"
            f"**AI Analysis:** Flagged as {threat_type.upper()} with an urgency score of {urgency}/10.\n\n"
            f"---\n**RAW EXTRACTED TEXT:**\n\n> {raw_text}"
        )

        # --- UPDATED: Removed generic "i2p" and "darkweb" tags for cleaner OpenCTI clustering ---
        report_labels = [threat_type, f"urgency:{urgency}"]

        report = Report(
            name=f"Automated Threat Flag: {threat_type.upper()} [Urgency: {urgency}/10]",
            description=formatted_description,
            published=datetime.utcnow(),
            object_refs=[obj.id for obj in stix_objects if obj.id != self.twip_identity.id],
            created_by_ref=self.twip_identity.id,
            labels=report_labels
        )
        stix_objects.append(report)

        # 4. Package everything into a STIX Bundle
        bundle = Bundle(objects=stix_objects)
        return bundle.serialize(indent=4)