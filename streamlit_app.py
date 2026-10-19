import streamlit as st
import os
import time
import hashlib
import sqlite3
import pandas as pd
from datetime import datetime
import tempfile

# Engine imports
from heuristic_engine import HeuristicScanner
from ml_engine import MLScanner
from yara_engine import YaraScanner

# --- Page Configuration ---
st.set_page_config(
    page_title="AI Malware Analysis System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- Professional Minimalist CSS ---
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

    :root {
        --bg-color: #f8fafc;
        --sidebar-bg: #1e293b;
        --card-bg: #ffffff;
        --primary-blue: #2563eb;
        --text-color: #0f172a;
        --danger-red: #dc2626;
        --success-green: #16a34a;
        --border-color: #e2e8f0;
        --muted-text: #64748b;
    }

    html, body, [data-testid="stAppViewContainer"] {
        font-family: 'Inter', sans-serif;
        background-color: var(--bg-color);
        color: var(--text-color);
    }

    /* Sidebar Styling */
    [data-testid="stSidebar"] {
        background-color: var(--sidebar-bg) !important;
        border-right: 1px solid var(--border-color);
    }
    
    [data-testid="stSidebar"] * {
        color: #ffffff !important;
    }

    /* Clean Card Styling */
    .stat-card {
        background-color: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 24px;
        box-shadow: 0 1px 2px rgba(0,0,0,0.05);
        text-align: center;
    }

    .stat-title { 
        color: var(--muted-text); 
        font-size: 0.875rem; 
        font-weight: 600; 
        margin-bottom: 8px;
        text-transform: uppercase;
        letter-spacing: 0.025em;
    }
    
    .stat-value { 
        color: var(--text-color); 
        font-size: 2rem; 
        font-weight: 700; 
    }

    /* Buttons */
    .stButton>button {
        background-color: var(--primary-blue) !important;
        color: white !important;
        border: none !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        padding: 0.6rem 1.2rem !important;
        transition: all 0.2s ease;
    }
    
    .stButton>button:hover {
        background-color: #1d4ed8 !important;
        transform: translateY(-1px);
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
    }

    /* File Uploader */
    [data-testid="stFileUploadDropzone"] {
        background-color: var(--card-bg);
        border: 2px dashed var(--border-color);
        border-radius: 8px;
    }

    /* Badges */
    .badge {
        display: inline-block;
        padding: 4px 12px;
        border-radius: 4px;
        font-size: 12px;
        font-weight: 600;
        text-transform: uppercase;
    }
    .badge-high { background-color: #fee2e2; color: #dc2626; border: 1px solid #fecaca; }
    .badge-medium { background-color: #fef3c7; color: #d97706; border: 1px solid #fde68a; }
    .badge-low { background-color: #dcfce7; color: #16a34a; border: 1px solid #bbf7d0; }

    /* Containers */
    .panel-box {
        background-color: var(--card-bg);
        border: 1px solid var(--border-color);
        border-radius: 8px;
        padding: 24px;
        margin-bottom: 20px;
    }

    .console-box {
        background-color: #f1f5f9;
        border: 1px solid var(--border-color);
        border-radius: 6px;
        padding: 16px;
        font-family: 'ui-monospace', 'SFMono-Regular', Menlo, Monaco, Consolas, monospace;
        color: #334155;
        font-size: 0.875rem;
        line-height: 1.5;
    }
    
    h1, h2, h3, h4 {
        color: var(--text-color) !important;
        font-weight: 700 !important;
    }
</style>
""", unsafe_allow_html=True)

# --- State Management ---
if 'engines_loaded' not in st.session_state:
    try:
        st.session_state.heuristic_engine = HeuristicScanner()
    except: st.session_state.heuristic_engine = None
    
    try:
        st.session_state.ml_engine = MLScanner()
    except: st.session_state.ml_engine = None
    
    try:
        st.session_state.yara_engine = YaraScanner()
    except: st.session_state.yara_engine = None
    
    st.session_state.engines_loaded = True

if 'activity_log' not in st.session_state:
    st.session_state.activity_log = [
        f"• [{datetime.now().strftime('%H:%M:%S')}] Scanner initialized successfully.",
        f"• [{datetime.now().strftime('%H:%M:%S')}] Waiting for file upload."
    ]

# --- Database Management ---
DB_PATH = "scanner_data.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS scan_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT NOT NULL, verdict TEXT NOT NULL,
        risk TEXT, heuristic TEXT, ml TEXT, final_score TEXT, file_hash TEXT, scan_time TEXT NOT NULL)""")
    c.execute("""CREATE TABLE IF NOT EXISTS quarantine (
        id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT NOT NULL, score REAL NOT NULL, added_time TEXT NOT NULL)""")
    conn.commit()
    conn.close()

init_db()

def get_stats():
    conn = sqlite3.connect(DB_PATH)
    history_df = pd.read_sql_query("SELECT * FROM scan_history ORDER BY id DESC", conn)
    quarantine_df = pd.read_sql_query("SELECT * FROM quarantine ORDER BY id DESC", conn)
    conn.close()
    
    scans = len(history_df)
    clean = len(history_df[history_df['verdict'] == 'CLEAN']) if scans > 0 else 0
    susp = len(history_df[history_df['verdict'] == 'SUSPICIOUS']) if scans > 0 else 0
    threats = len(history_df[history_df['verdict'] == 'MALICIOUS']) if scans > 0 else 0
    
    return scans, threats, clean, susp, history_df, quarantine_df

scans, threats, clean, susp, history_df, quarantine_df = get_stats()

# --- Utility Functions ---
def compute_sha256(filepath):
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def log_activity(msg):
    st.session_state.activity_log.insert(0, f"• [{datetime.now().strftime('%H:%M:%S')}] {msg}")

# --- Sidebar Navigation ---
st.sidebar.markdown("<h2 style='text-align: center; margin-bottom: 0;'>🛡️ SecureScan</h2>", unsafe_allow_html=True)
st.sidebar.markdown("<p style='text-align: center; font-size: 0.8rem; opacity: 0.8;'>Hybrid Malware Analysis System</p>", unsafe_allow_html=True)
st.sidebar.markdown("<br>", unsafe_allow_html=True)

nav_map = {
    "📊 Overview": "Overview Dashboard",
    "🔍 Analyze File": "Analyze File",
    "📜 Scan Logs": "Scan Logs",
    "🛡️ Quarantine": "Quarantine Management"
}
choice_icon = st.sidebar.radio("Navigation Menu", list(nav_map.keys()))
choice = nav_map[choice_icon]

# --- Views ---
if choice == "Overview Dashboard":
    st.markdown("## System Overview")
    
    # 4 Stat Cards
    c1, c2, c3, c4 = st.columns(4)
    def stat_card(title, value, color):
        return f"""
        <div class='stat-card'>
            <div class='stat-title'>{title}</div>
            <div class='stat-value' style='color: {color};'>{value}</div>
        </div>
        """
        
    with c1: st.markdown(stat_card("Files Scanned", scans, "var(--primary-blue)"), unsafe_allow_html=True)
    with c2: st.markdown(stat_card("Suspicious Files", threats + susp, "var(--danger-red)"), unsafe_allow_html=True)
    with c3: st.markdown(stat_card("Quarantined", len(quarantine_df), "#d97706"), unsafe_allow_html=True)
    with c4: st.markdown(stat_card("System Status", "Operational", "var(--success-green)"), unsafe_allow_html=True)
        
    st.markdown("<br>", unsafe_allow_html=True)
    
    col_left, col_right = st.columns([2, 1])
    
    with col_left:
        st.markdown("### Recent Scan Activity")
        if not history_df.empty:
            st.dataframe(history_df[['filename', 'verdict', 'risk', 'scan_time']].head(10), use_container_width=True)
        else:
            st.info("No recent scan activity recorded.")

    with col_right:
        st.markdown("### Threat Alerts")
        threat_logs = history_df[history_df['verdict'] != 'File Appears Safe'].head(5)
        if not threat_logs.empty:
            for _, row in threat_logs.iterrows():
                badge_class = "badge-high" if row['risk'] == 'HIGH' else "badge-medium"
                st.markdown(f"""
                <div style='padding: 12px; border-bottom: 1px solid var(--border-color);'>
                    <div style='display: flex; justify-content: space-between; align-items: center;'>
                        <span style='font-weight: 600; font-size: 0.9rem;'>{row['filename'][:20]}...</span>
                        <span class='badge {badge_class}'>{row['verdict']}</span>
                    </div>
                    <div style='font-size: 0.75rem; color: var(--muted-text); margin-top: 4px;'>{row['scan_time']}</div>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.success("No active threats identified.")

elif choice == "Analyze File":
    st.markdown("## Analyze File")
    
    # Reset result visibility on new file upload
    if 'show_analysis' not in st.session_state:
        st.session_state.show_analysis = False

    col_up, col_act = st.columns([3, 1])
    with col_up:
        uploaded_file = st.file_uploader("Upload Executable for Risk Assessment", help="Supported formats: .exe, .dll, .sys")
    with col_act:
        st.markdown("<br>", unsafe_allow_html=True)
        analyze_btn = st.button("Initialize Analysis", use_container_width=True, type="primary")

    if uploaded_file is not None and analyze_btn:
        with st.spinner("Processing file indicators..."):
            # Save to temp file
            with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as tmp_file:
                tmp_file.write(uploaded_file.getvalue())
                tmp_path = tmp_file.name
            
            filename = uploaded_file.name
            log_activity(f"Analysis started: {filename}")
            
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Hash
            status_text.markdown(f"**HASH** - Verifying file signature: {filename}")
            file_hash = compute_sha256(tmp_path)
            progress_bar.progress(25); time.sleep(0.3)
            
            # Heuristic
            status_text.markdown(f"**HEURISTIC** - Analyzing behavior patterns: {filename}")
            h_res = st.session_state.heuristic_engine.scan_file(tmp_path) if st.session_state.heuristic_engine else {"error": "Unavailable"}
            progress_bar.progress(50); time.sleep(0.3)
            
            # ML
            status_text.markdown(f"**ML MODEL** - Performing statistical risk evaluation: {filename}")
            m_res = st.session_state.ml_engine.scan_file(tmp_path) if st.session_state.ml_engine else {"error": "Unavailable"}
            progress_bar.progress(75); time.sleep(0.3)
            
            # YARA
            status_text.markdown(f"**YARA** - Checking known threat indicators: {filename}")
            y_res = st.session_state.yara_engine.scan_file(tmp_path) if st.session_state.yara_engine else {"error": "Unavailable"}
            progress_bar.progress(100); time.sleep(0.3)
            
            status_text.markdown(f"**COMPLETED** - Analysis finished for: {filename}")
            
            # Cleanup temp file
            try: os.remove(tmp_path)
            except: pass
            
            # --- Result Logic ---
            h_score = h_res.get("score", 0) if "error" not in h_res else 0
            h_text = f"Risk Score: {h_score}/100"
            m_score = m_res.get("score", 0) if "error" not in m_res else 0
            m_family = m_res.get("family", "Benign") if "error" not in m_res else "N/A"
            m_text = f"{m_score:.1f}% ({m_family})"
            y_score = y_res.get("score", 0) if y_res and "error" not in y_res and y_res.get("matches") else 0
            y_text = f"{len(y_res['matches'])} indicators matched" if y_res.get("matches") else "No matches"
            
            base_score = (h_score * 0.4) + (m_score * 0.6) if m_score > 0 else h_score
            final_score_value = max(base_score, y_score)
            final_score_text = f"{final_score_value:.1f}/100"
            scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            if final_score_value >= 60:
                verdict, risk, v_class = "High-Risk File", "HIGH", "badge-high"
                summary = "Significant suspicious patterns and threat indicators identified."
                action = "Immediate quarantine or sandboxed analysis recommended."
                log_activity(f"High-risk indicators found: {filename}")
                conn = sqlite3.connect(DB_PATH)
                conn.execute("INSERT INTO quarantine (filename, score, added_time) VALUES (?, ?, ?)", (filename, final_score_value, scan_time))
                conn.commit(); conn.close()
            elif final_score_value >= 30:
                verdict, risk, v_class = "Suspicious File Detected", "MEDIUM", "badge-medium"
                summary = "File exhibits unusual characteristics that require attention."
                action = "Review file behavior before execution."
                log_activity(f"Suspicious behavior detected: {filename}")
            else:
                verdict, risk, v_class = "File Appears Safe", "LOW", "badge-low"
                summary = "No significant threat indicators or suspicious patterns detected."
                action = "Standard operational usage likely safe."
                log_activity(f"Analysis complete: no threats identified in {filename}")
            
            # Save to Session State
            st.session_state.last_analysis = {
                "filename": filename, "verdict": verdict, "risk": risk, "h_text": h_text, 
                "m_text": m_text, "y_text": y_text, "final_score": final_score_text, 
                "hash": file_hash, "time": scan_time, "v_class": v_class, "summary": summary,
                "status": "Latest Assessment", "action": action
            }
            st.session_state.show_analysis = True
            
            # Save to Database
            conn = sqlite3.connect(DB_PATH)
            conn.execute("INSERT INTO scan_history (filename, verdict, risk, heuristic, ml, final_score, file_hash, scan_time) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                         (filename, verdict, risk, h_text, m_text, final_score_text, file_hash, scan_time))
            conn.commit(); conn.close()
            st.rerun()

    # --- Render Assessment (If triggered) ---
    if st.session_state.show_analysis and st.session_state.last_analysis:
        res = st.session_state.last_analysis
        v_class = res.get("v_class", "badge-low")
        summary = res.get("summary", "Analysis results for the selected file.")
        
        # Render Result with Native Streamlit Components
        st.markdown("---")
        st.subheader(f"Analysis Results: {res['filename']}")
        
        # Verdict Header
        if res['risk'] == "HIGH":
            st.error(f"**{res['verdict']}** - {res['summary']}")
        elif res['risk'] == "MEDIUM":
            st.warning(f"**{res['verdict']}** - {res['summary']}")
        else:
            st.success(f"**{res['verdict']}** - {res['summary']}")

        # Metrics Row
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("⚖️ Risk Level", res['risk'])
        m2.metric("🧠 Behavioral", res['h_text'])
        m3.metric("🤖 AI Confidence", res['m_text'])
        m4.metric("📈 Risk Score", res['final_score'])

        # Details Expander
        with st.expander("Detailed Technical Indicators", expanded=True):
            col_left, col_right = st.columns(2)
            with col_left:
                st.markdown("**File Properties**")
                st.text(f"Filename: {res['filename']}")
                st.text(f"SHA-256: {res['hash']}")
                st.text(f"Scan Time: {res['time']}")
            with col_right:
                st.markdown("**Threat Intelligence**")
                st.text(f"Heuristic Status: {res['h_text']}")
                st.text(f"ML Interpretation: {res['m_text']}")
                st.text(f"YARA Match Status: {res.get('y_text', 'No matches')}")

        # Recommended Action
        st.info(f"**Recommended Protocol:** {res.get('action', 'Monitor file activity.')}")
        
        # Real Streamlit Download Buttons
        c_dl1, c_dl2, _ = st.columns([1, 1, 2])
        with c_dl1:
            report_csv = pd.DataFrame([res]).to_csv(index=False)
            st.download_button("Download CSV Report", data=report_csv, file_name=f"assessment_{res['filename']}.csv", mime="text/csv", use_container_width=True)
        with c_dl2:
            import json
            report_json = json.dumps(res, indent=4)
            st.download_button("Export as JSON", data=report_json, file_name=f"assessment_{res['filename']}.json", mime="application/json", use_container_width=True)
    else:
        st.info("Ready for analysis. Please upload an executable file above to begin.")

elif choice == "Scan Logs":
    st.markdown("## Scan Logs")
    if not history_df.empty:
        st.dataframe(history_df, use_container_width=True)
    else:
        st.info("No scan logs found.")

elif choice == "Quarantine Management":
    st.markdown("## Quarantine Management")
    if not quarantine_df.empty:
        st.dataframe(quarantine_df, use_container_width=True)
        if st.button("Clear Quarantine"):
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM quarantine")
            conn.commit(); conn.close()
            st.rerun()
    else:
        st.success("Quarantine is currently empty.")


