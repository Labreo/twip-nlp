import streamlit as st
import requests
import json
import os
import glob
from datetime import datetime
from collections import defaultdict
import time

# ─────────────────────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────────────────────
ORCHESTRATOR_URL = "http://localhost:5001"
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")

st.set_page_config(
    page_title="TWIP — DarkWeb Intelligence",
    page_icon="🕸️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────────────────────────────────────
# STYLES
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #080c10;
    color: #c9d1d9;
}

.stApp {
    background: #080c10;
}

/* Scanline overlay */
.stApp::before {
    content: "";
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: repeating-linear-gradient(
        0deg,
        transparent,
        transparent 2px,
        rgba(0,255,100,0.015) 2px,
        rgba(0,255,100,0.015) 4px
    );
    pointer-events: none;
    z-index: 9999;
}

h1, h2, h3 {
    font-family: 'Share Tech Mono', monospace !important;
    color: #00ff88 !important;
    letter-spacing: 0.05em;
}

.metric-card {
    background: linear-gradient(135deg, #0d1117 0%, #0a1628 100%);
    border: 1px solid #00ff8833;
    border-left: 3px solid #00ff88;
    border-radius: 4px;
    padding: 16px 20px;
    margin-bottom: 12px;
    box-shadow: 0 0 20px rgba(0,255,136,0.05);
}

.metric-value {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.4rem;
    color: #00ff88;
    line-height: 1;
    margin: 4px 0;
}

.metric-label {
    font-size: 0.75rem;
    color: #8b949e;
    letter-spacing: 0.1em;
    text-transform: uppercase;
}

.threat-row {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 4px;
    padding: 12px 16px;
    margin-bottom: 8px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
    transition: border-color 0.2s;
}

.threat-row:hover {
    border-color: #00ff8855;
}

.urgency-high { border-left: 3px solid #ff4444; }
.urgency-med  { border-left: 3px solid #ff9900; }
.urgency-low  { border-left: 3px solid #00ff88; }

.tag {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 2px;
    font-size: 0.7rem;
    font-family: 'Share Tech Mono', monospace;
    margin-right: 4px;
    letter-spacing: 0.05em;
}

.tag-cyber    { background: #1a2a4a; color: #4fc3f7; border: 1px solid #4fc3f755; }
.tag-drug     { background: #2a1a2a; color: #ce93d8; border: 1px solid #ce93d855; }
.tag-fraud    { background: #2a2a1a; color: #ffcc02; border: 1px solid #ffcc0255; }
.tag-weapons  { background: #2a1a1a; color: #ff7043; border: 1px solid #ff704355; }
.tag-benign   { background: #1a2a1a; color: #00ff88; border: 1px solid #00ff8855; }
.tag-unknown  { background: #1a1a1a; color: #8b949e; border: 1px solid #8b949e55; }

.status-online  { color: #00ff88; font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; }
.status-offline { color: #ff4444; font-family: 'Share Tech Mono', monospace; font-size: 0.8rem; }

.wallet-addr {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    color: #ffcc02;
    background: #1a1a00;
    padding: 2px 6px;
    border-radius: 2px;
    word-break: break-all;
}

.cve-badge {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    color: #ff4444;
    background: #1a0000;
    padding: 2px 6px;
    border-radius: 2px;
    margin: 2px;
    display: inline-block;
}

.sidebar-header {
    font-family: 'Share Tech Mono', monospace;
    color: #00ff88;
    font-size: 1.1rem;
    border-bottom: 1px solid #00ff8833;
    padding-bottom: 8px;
    margin-bottom: 16px;
}

div[data-testid="stSidebar"] {
    background: #0a0e13;
    border-right: 1px solid #00ff8822;
}

.stButton > button {
    background: transparent;
    border: 1px solid #00ff8866;
    color: #00ff88;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
    letter-spacing: 0.05em;
    transition: all 0.2s;
}

.stButton > button:hover {
    background: #00ff8811;
    border-color: #00ff88;
}

.actor-card {
    background: #0d1117;
    border: 1px solid #21262d;
    border-radius: 4px;
    padding: 12px;
    margin-bottom: 8px;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
}

.actor-name {
    color: #00ff88;
    font-size: 0.9rem;
    font-weight: bold;
    margin-bottom: 6px;
}

.divider {
    border: none;
    border-top: 1px solid #21262d;
    margin: 16px 0;
}
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────────────────────────────────────
def get_pipeline_status():
    try:
        r = requests.get(f"{ORCHESTRATOR_URL}/status", timeout=3)
        if r.status_code == 200:
            return r.json()
    except:
        pass
    return None

def load_stix_bundles():
    bundles = []
    pattern = os.path.join(OUTPUT_DIR, "**", "stix_bundle_*.json")
    files = sorted(glob.glob(pattern, recursive=True), key=os.path.getmtime, reverse=True)
    for f in files[:50]:  # cap at 50 most recent
        try:
            with open(f, 'r') as fp:
                data = json.load(fp)
                data["_filename"] = os.path.basename(f)
                data["_mtime"] = os.path.getmtime(f)
                bundles.append(data)
        except:
            continue
    return bundles

def parse_bundle(bundle):
    """Extract key fields from a STIX bundle for display."""
    objects = bundle.get("objects", [])
    result = {
        "filename": bundle.get("_filename", "unknown"),
        "timestamp": datetime.fromtimestamp(bundle.get("_mtime", 0)).strftime("%Y-%m-%d %H:%M:%S"),
        "actor": None,
        "aliases": [],
        "category": "unknown",
        "urgency": 0,
        "wallets": [],
        "cves": [],
        "malware": [],
        "tools": [],
        "indicators": 0,
        "report_name": ""
    }

    for obj in objects:
        t = obj.get("type", "")
        if t == "threat-actor":
            result["actor"] = obj.get("name", "Unknown")
            result["aliases"] = obj.get("aliases", [])
        elif t == "report":
            name = obj.get("name", "")
            result["report_name"] = name
            # Parse category and urgency from report name
            # Format: "Automated Threat Flag: CATEGORY [Urgency: X/10]"
            if "Urgency:" in name:
                try:
                    urg = name.split("Urgency:")[1].split("/")[0].strip()
                    result["urgency"] = int(urg)
                except:
                    pass
            labels = obj.get("labels", [])
            for label in labels:
                if label not in ["darkweb", "i2p"]:
                    result["category"] = label
                    break
        elif t == "indicator":
            result["indicators"] += 1
            pattern = obj.get("pattern", "")
            if "wallet_address" in pattern:
                addr = pattern.split("'")[1] if "'" in pattern else ""
                if addr:
                    result["wallets"].append(addr)
        elif t == "vulnerability":
            result["cves"].append(obj.get("name", ""))
        elif t == "malware":
            result["malware"].append(obj.get("name", ""))
        elif t == "tool":
            result["tools"].append(obj.get("name", ""))

    return result

def category_tag(cat):
    tag_map = {
        "hacking_services": ("CYBERCRIME", "tag-cyber"),
        "drug_sales": ("DRUGS", "tag-drug"),
        "financial_fraud": ("FRAUD", "tag-fraud"),
        "weapons": ("WEAPONS", "tag-weapons"),
        "benign": ("BENIGN", "tag-benign"),
        "csam_references": ("CSAM", "tag-weapons"),
    }
    label, cls = tag_map.get(cat, (cat.upper(), "tag-unknown"))
    return f'<span class="tag {cls}">{label}</span>'

def urgency_class(score):
    if score >= 7: return "urgency-high"
    if score >= 4: return "urgency-med"
    return "urgency-low"

# ─────────────────────────────────────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="sidebar-header">⬡ TWIP CONTROL</div>', unsafe_allow_html=True)

    status = get_pipeline_status()
    if status:
        st.markdown('<span class="status-online">● PIPELINE ONLINE</span>', unsafe_allow_html=True)
        stats = status.get("stats", {})
        st.markdown(f"""
        <div style="font-family: 'Share Tech Mono', monospace; font-size: 0.75rem; color: #8b949e; margin-top: 8px; line-height: 2;">
        POSTS PROCESSED: <span style="color:#00ff88">{stats.get('unique_posts_processed', 0)}</span><br>
        THREAT ACTORS: <span style="color:#00ff88">{stats.get('known_threat_actors', 0)}</span><br>
        STIX BUNDLES: <span style="color:#00ff88">{stats.get('stix_bundles_generated', 0)}</span><br>
        LLM BACKEND: <span style="color:#4fc3f7">Llama 3 (local)</span><br>
        NETWORK: <span style="color:#ce93d8">I2P</span>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown('<span class="status-offline">● PIPELINE OFFLINE</span>', unsafe_allow_html=True)
        st.markdown('<div style="font-family: Share Tech Mono, monospace; font-size: 0.7rem; color: #8b949e; margin-top: 8px;">Run pipeline/orchestrator.py<br>to bring the pipeline online.</div>', unsafe_allow_html=True)

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)

    st.markdown('<div style="font-family: Share Tech Mono, monospace; font-size: 0.75rem; color: #8b949e; text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 8px;">Filters</div>', unsafe_allow_html=True)

    cat_filter = st.multiselect(
        "Category",
        ["hacking_services", "drug_sales", "financial_fraud", "weapons", "benign", "csam_references"],
        default=[],
        label_visibility="collapsed"
    )

    urgency_filter = st.slider("Min Urgency Score", 0, 10, 0)

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)

    auto_refresh = st.checkbox("Auto-refresh (30s)", value=False)
    if st.button("↺  Refresh Now"):
        st.rerun()

    st.markdown("<hr class='divider'>", unsafe_allow_html=True)
    st.markdown('<div style="font-family: Share Tech Mono, monospace; font-size: 0.65rem; color: #444; text-align: center;">TWIP NLP ENGINE v1.0<br>OSINT • STIX 2.1 • I2P</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# MAIN HEADER
# ─────────────────────────────────────────────────────────────────────────────
st.markdown("""
<div style="border-bottom: 1px solid #00ff8822; padding-bottom: 16px; margin-bottom: 24px;">
    <h1 style="margin: 0; font-size: 1.8rem;">⬡ TWIP — DARKWEB INTELLIGENCE PLATFORM</h1>
    <div style="font-family: 'Share Tech Mono', monospace; font-size: 0.75rem; color: #8b949e; margin-top: 4px;">
        AUTOMATED NLP THREAT DETECTION • STIX 2.1 OUTPUT • OPENCTI INTEGRATION
    </div>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# LOAD & FILTER BUNDLES
# ─────────────────────────────────────────────────────────────────────────────
bundles = load_stix_bundles()
parsed = [parse_bundle(b) for b in bundles]

if cat_filter:
    parsed = [p for p in parsed if p["category"] in cat_filter]
parsed = [p for p in parsed if p["urgency"] >= urgency_filter]

# ─────────────────────────────────────────────────────────────────────────────
# TOP METRICS
# ─────────────────────────────────────────────────────────────────────────────
col1, col2, col3, col4, col5 = st.columns(5)

total = len(parsed)
high_urgency = sum(1 for p in parsed if p["urgency"] >= 7)
unique_actors = len(set(p["actor"] for p in parsed if p["actor"]))
total_cves = len(set(cve for p in parsed for cve in p["cves"]))
total_wallets = len(set(w for p in parsed for w in p["wallets"]))

with col1:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Total Bundles</div><div class="metric-value">{total}</div></div>', unsafe_allow_html=True)
with col2:
    st.markdown(f'<div class="metric-card"><div class="metric-label">High Urgency</div><div class="metric-value" style="color:#ff4444">{high_urgency}</div></div>', unsafe_allow_html=True)
with col3:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Threat Actors</div><div class="metric-value">{unique_actors}</div></div>', unsafe_allow_html=True)
with col4:
    st.markdown(f'<div class="metric-card"><div class="metric-label">CVEs Tracked</div><div class="metric-value" style="color:#ff9900">{total_cves}</div></div>', unsafe_allow_html=True)
with col5:
    st.markdown(f'<div class="metric-card"><div class="metric-label">Wallets Flagged</div><div class="metric-value" style="color:#ffcc02">{total_wallets}</div></div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["📡  Threat Feed", "👤  Actors", "🔑  IOCs", "📊  Analytics"])

# ── TAB 1: THREAT FEED ────────────────────────────────────────────────────────
with tab1:
    if not parsed:
        st.markdown('<div style="font-family: Share Tech Mono, monospace; color: #8b949e; padding: 40px; text-align: center;">NO BUNDLES FOUND — Run mock_crawler.py or auto_ingester.py to populate</div>', unsafe_allow_html=True)
    else:
        for p in parsed:
            urg_cls = urgency_class(p["urgency"])
            urgency_color = "#ff4444" if p["urgency"] >= 7 else "#ff9900" if p["urgency"] >= 4 else "#00ff88"
            cat_html = category_tag(p["category"])
            actor_display = p["actor"] or "Unknown Actor"
            aliases_html = ""
            if p["aliases"]:
                aliases_html = " ".join([f'<span style="color:#8b949e; font-size:0.7rem">≡ {a}</span>' for a in p["aliases"][:3]])

            malware_html = " ".join([f'<span style="color:#ff7043; font-size:0.7rem">▸ {m}</span>' for m in p["malware"][:3]])
            tools_html = " ".join([f'<span style="color:#4fc3f7; font-size:0.7rem">⚙ {t}</span>' for t in p["tools"][:3]])

            st.markdown(f"""
            <div class="threat-row {urg_cls}">
                <div style="display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:6px;">
                    <div>
                        <span style="color:#00ff88; font-size:0.9rem;">{actor_display}</span>
                        &nbsp;{aliases_html}
                    </div>
                    <div style="text-align:right;">
                        {cat_html}
                        <span style="font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:{urgency_color}; margin-left:8px;">⚠ {p['urgency']}/10</span>
                    </div>
                </div>
                <div style="color:#8b949e; font-size:0.7rem; margin-bottom:4px;">
                    {p['timestamp']} &nbsp;·&nbsp; {p['filename']} &nbsp;·&nbsp; {p['indicators']} indicators
                </div>
                <div>{malware_html} {tools_html}</div>
            </div>
            """, unsafe_allow_html=True)

# ── TAB 2: ACTORS ─────────────────────────────────────────────────────────────
with tab2:
    actor_map = defaultdict(lambda: {"categories": set(), "urgency_scores": [], "cves": set(), "wallets": set(), "aliases": set(), "malware": set()})

    for p in parsed:
        if not p["actor"]:
            continue
        a = actor_map[p["actor"]]
        a["categories"].add(p["category"])
        a["urgency_scores"].append(p["urgency"])
        a["cves"].update(p["cves"])
        a["wallets"].update(p["wallets"])
        a["aliases"].update(p["aliases"])
        a["malware"].update(p["malware"])

    if not actor_map:
        st.markdown('<div style="font-family: Share Tech Mono, monospace; color: #8b949e; padding: 40px; text-align: center;">NO ACTOR DATA AVAILABLE</div>', unsafe_allow_html=True)
    else:
        sorted_actors = sorted(actor_map.items(), key=lambda x: max(x[1]["urgency_scores"]) if x[1]["urgency_scores"] else 0, reverse=True)
        cols = st.columns(2)
        for i, (actor, data) in enumerate(sorted_actors):
            max_urg = max(data["urgency_scores"]) if data["urgency_scores"] else 0
            avg_urg = round(sum(data["urgency_scores"]) / len(data["urgency_scores"]), 1) if data["urgency_scores"] else 0
            urg_color = "#ff4444" if max_urg >= 7 else "#ff9900" if max_urg >= 4 else "#00ff88"
            cats_html = " ".join([category_tag(c) for c in data["categories"]])
            aliases_str = ", ".join(list(data["aliases"])[:4]) or "None"
            malware_str = ", ".join(list(data["malware"])[:4]) or "None"
            cves_str = ", ".join(list(data["cves"])[:3]) or "None"

            with cols[i % 2]:
                st.markdown(f"""
                <div class="actor-card">
                    <div class="actor-name">👤 {actor}</div>
                    <div style="margin-bottom:6px;">{cats_html}</div>
                    <div style="color:#8b949e; line-height:1.8;">
                        MAX URGENCY: <span style="color:{urg_color}">{max_urg}/10</span> &nbsp;·&nbsp; AVG: <span style="color:{urg_color}">{avg_urg}</span><br>
                        ALIASES: <span style="color:#c9d1d9">{aliases_str}</span><br>
                        MALWARE: <span style="color:#ff7043">{malware_str}</span><br>
                        CVEs: <span style="color:#ff4444">{cves_str}</span><br>
                        WALLETS: <span style="color:#ffcc02">{len(data['wallets'])}</span>
                    </div>
                </div>
                """, unsafe_allow_html=True)

# ── TAB 3: IOCs ───────────────────────────────────────────────────────────────
with tab3:
    ioc_col1, ioc_col2 = st.columns(2)

    with ioc_col1:
        st.markdown("### 🔑 Crypto Wallets")
        all_wallets = [(w, p["actor"], p["category"]) for p in parsed for w in p["wallets"]]
        seen_w = set()
        unique_wallets = []
        for w, actor, cat in all_wallets:
            if w not in seen_w:
                seen_w.add(w)
                unique_wallets.append((w, actor, cat))

        if not unique_wallets:
            st.markdown('<div style="font-family: Share Tech Mono, monospace; color: #8b949e;">No wallets extracted</div>', unsafe_allow_html=True)
        else:
            for w, actor, cat in unique_wallets[:20]:
                st.markdown(f"""
                <div style="margin-bottom:8px;">
                    <div class="wallet-addr">{w}</div>
                    <div style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#8b949e; margin-top:2px;">
                        {actor or 'Unknown'} · {category_tag(cat)}
                    </div>
                </div>
                """, unsafe_allow_html=True)

    with ioc_col2:
        st.markdown("### 💀 CVEs & Vulnerabilities")
        all_cves = [(cve, p["actor"]) for p in parsed for cve in p["cves"]]
        seen_cves = set()
        unique_cves = []
        for cve, actor in all_cves:
            if cve not in seen_cves:
                seen_cves.add(cve)
                unique_cves.append((cve, actor))

        if not unique_cves:
            st.markdown('<div style="font-family: Share Tech Mono, monospace; color: #8b949e;">No CVEs extracted</div>', unsafe_allow_html=True)
        else:
            for cve, actor in unique_cves[:20]:
                st.markdown(f"""
                <div style="margin-bottom:8px;">
                    <span class="cve-badge">{cve}</span>
                    <span style="font-family:'Share Tech Mono',monospace; font-size:0.65rem; color:#8b949e; margin-left:6px;">
                        linked to {actor or 'Unknown'}
                    </span>
                </div>
                """, unsafe_allow_html=True)

        st.markdown("### 🦠 Malware Families")
        all_malware = [(m, p["actor"]) for p in parsed for m in p["malware"]]
        seen_mal = set()
        unique_mal = []
        for m, actor in all_malware:
            if m not in seen_mal:
                seen_mal.add(m)
                unique_mal.append((m, actor))

        if not unique_mal:
            st.markdown('<div style="font-family: Share Tech Mono, monospace; color: #8b949e;">No malware extracted</div>', unsafe_allow_html=True)
        else:
            for m, actor in unique_mal[:10]:
                st.markdown(f"""
                <span style="font-family:'Share Tech Mono',monospace; font-size:0.75rem; color:#ff7043; background:#1a0a00; padding:3px 8px; border-radius:2px; margin:2px; display:inline-block;">
                    ▸ {m}
                </span>
                """, unsafe_allow_html=True)

# ── TAB 4: ANALYTICS ──────────────────────────────────────────────────────────
with tab4:
    an_col1, an_col2 = st.columns(2)

    with an_col1:
        st.markdown("### 📊 Threats by Category")
        cat_counts = defaultdict(int)
        for p in parsed:
            cat_counts[p["category"]] += 1

        if cat_counts:
            import streamlit as st2
            cat_labels = list(cat_counts.keys())
            cat_values = list(cat_counts.values())
            st.bar_chart({k: v for k, v in cat_counts.items()})
        else:
            st.markdown('<div style="font-family: Share Tech Mono, monospace; color: #8b949e;">No data</div>', unsafe_allow_html=True)

    with an_col2:
        st.markdown("### ⚠ Urgency Distribution")
        urg_buckets = {"0-3 (Low)": 0, "4-6 (Med)": 0, "7-10 (High)": 0}
        for p in parsed:
            u = p["urgency"]
            if u <= 3: urg_buckets["0-3 (Low)"] += 1
            elif u <= 6: urg_buckets["4-6 (Med)"] += 1
            else: urg_buckets["7-10 (High)"] += 1

        st.bar_chart(urg_buckets)

    st.markdown("### 🕸 Actor Co-occurrence (Shared Identifiers)")
    if parsed:
        # Show a simple table of actors and their connection count
        actor_connections = defaultdict(int)
        for p in parsed:
            if p["actor"] and p["aliases"]:
                actor_connections[p["actor"]] += len(p["aliases"])

        if actor_connections:
            rows = [{"Actor": k, "Linked Aliases": v} for k, v in sorted(actor_connections.items(), key=lambda x: x[1], reverse=True)]
            st.dataframe(rows, use_container_width=True, hide_index=True)
        else:
            st.markdown('<div style="font-family: Share Tech Mono, monospace; color: #8b949e;">No alias links detected yet</div>', unsafe_allow_html=True)

# ─────────────────────────────────────────────────────────────────────────────
# AUTO REFRESH
# ─────────────────────────────────────────────────────────────────────────────
if auto_refresh:
    time.sleep(30)
    st.rerun()
