import streamlit as st
import time
import pandas as pd
import random

# --- CONFIGURATION ---
st.set_page_config(
    page_title="Splunk Threat Hunter",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS for that "Cyber Security" look
st.markdown("""
    <style>
    .stApp {
        background-color: #0f172a;
        color: #e2e8f0;
    }
    .stMetric {
        background-color: #1e293b;
        border: 1px solid #334155;
        padding: 15px;
        border-radius: 8px;
    }
    </style>
    """, unsafe_allow_html=True)

# --- 1. THE "SMART" MOCK SPLUNK API ---
def mock_splunk_api_query(query_str):
    with st.spinner(f"📡 Connecting to Splunk API... Running: '{query_str}'"):
        time.sleep(1.0) # Fake network delay
    
    # CASE A: DATA EXFILTRATION
    if "Data Exfiltration" in query_str:
        return [
            {"timestamp": "2024-01-14T14:20:01", "event": "Data_Exfil", "user": "finance_admin", "src_ip": "10.0.5.22", "dest_ip": "195.2.2.1", "bytes": "500MB", "status": "Allowed"},
            {"timestamp": "2024-01-14T14:20:05", "event": "Data_Exfil", "user": "finance_admin", "src_ip": "10.0.5.22", "dest_ip": "195.2.2.1", "bytes": "1.2GB", "status": "Allowed"},
            {"timestamp": "2024-01-14T14:21:00", "event": "Data_Exfil", "user": "finance_admin", "src_ip": "10.0.5.22", "dest_ip": "195.2.2.1", "bytes": "4.5GB", "status": "Blocked"},
            {"timestamp": "2024-01-14T14:22:00", "event": "Normal_Traffic", "user": "user_01", "src_ip": "10.0.5.30", "dest_ip": "8.8.8.8", "bytes": "12KB", "status": "Allowed"}
        ]

    # CASE B: MALWARE DETECTED
    elif "Malware" in query_str:
        return [
            {"timestamp": "2024-01-14T09:00:00", "event": "Malware_Detected", "user": "hr_manager", "src_ip": "192.168.1.10", "file": "invoice.exe", "hash": "bad_hash_123"},
            {"timestamp": "2024-01-14T09:05:00", "event": "Malware_Detected", "user": "hr_manager", "src_ip": "192.168.1.10", "file": "bonus.pdf.exe", "hash": "bad_hash_456"},
            {"timestamp": "2024-01-14T09:10:00", "event": "System_Clean", "user": "hr_manager", "src_ip": "192.168.1.10", "file": "clean_scan.log", "hash": "N/A"}
        ]

    # CASE C: FAILED LOGIN (Default)
    else:
        return [
            {"timestamp": "2024-01-14T10:01:00", "event": "Failed Login", "user": "admin", "src_ip": "192.168.1.5", "status": "401"},
            {"timestamp": "2024-01-14T10:01:02", "event": "Failed Login", "user": "admin", "src_ip": "192.168.1.5", "status": "401"},
            {"timestamp": "2024-01-14T10:01:05", "event": "Failed Login", "user": "root",  "src_ip": "45.33.22.11", "status": "401"},
            {"timestamp": "2024-01-14T10:01:06", "event": "Failed Login", "user": "root",  "src_ip": "45.33.22.11", "status": "401"},
            {"timestamp": "2024-01-14T10:01:07", "event": "Failed Login", "user": "root",  "src_ip": "45.33.22.11", "status": "401"},
            {"timestamp": "2024-01-14T10:02:00", "event": "Success Login", "user": "edgar", "src_ip": "10.0.0.5",    "status": "200"}
        ]

# --- 2. THREAT INTEL ENRICHMENT ---
def check_ip_reputation(ip_address):
    # Known bad IPs for the simulation
    known_bad_ips = ["45.33.22.11", "195.2.2.1", "103.4.5.6"]
    
    if ip_address in known_bad_ips:
        return "CRITICAL: Known Threat Actor"
    elif ip_address.startswith("192.168") or ip_address.startswith("10."):
        return "SAFE: Internal Network"
    else:
        return "UNKNOWN"

# --- 3. THE UI LAYOUT ---
def main():
    st.title("🛡️ Automated Threat Hunt Dashboard")
    st.markdown("### Integration: Splunk Enterprise Security")
    
    # Sidebar Controls
    st.sidebar.header("Search Parameters")
    index = st.sidebar.text_input("Splunk Index", "security")
    event_type = st.sidebar.selectbox("Event Type", ["Failed Login", "Data Exfiltration", "Malware Detected"])
    
    # The "Run" Button
    if st.sidebar.button("🚀 Run Threat Hunt"):
        
        # A. Query Splunk
        search_query = f'search index={index} event="{event_type}" | stats count by src_ip'
        st.info(f"Executing SPL: `{search_query}`")
        
        logs = mock_splunk_api_query(search_query)
        df_logs = pd.DataFrame(logs)
        
        # Display Raw Data
        st.subheader(f"📥 Retrieved {len(logs)} logs")
        st.dataframe(df_logs, use_container_width=True)
        
        # B. Parse & Analyze
        st.markdown("---")
        st.subheader("⚙️ Analysis & IOC Enrichment")
        
        suspicious_ips = {}
        results = []
        
        # Logic to count events per IP
        for log in logs:
            # Check different fields depending on the log type
            if 'src_ip' in log:
                ip = log['src_ip']
                suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

        # C. Display Alerts
        cols = st.columns(3)
        
        # Keep track if we found any threats to display appropriate message
        threat_found = False

        for ip, count in suspicious_ips.items():
            intel = check_ip_reputation(ip)
            
            # Create a nice result object for the table
            results.append({"Source IP": ip, "Event Count": count, "Threat Intel": intel})
            
            # Display Critical Alerts Prominently if count is high or Intel is CRITICAL
            if count >= 3 or "CRITICAL" in intel:
                threat_found = True
                with cols[0]:
                    if "CRITICAL" in intel:
                        st.error(f"🚨 **CRITICAL ALERT**\n\nIP: `{ip}`\n\nEvents: {count}\n\nIntel: {intel}")
                        st.button(f"🔥 Block {ip} on Firewall", key=ip)
                    else:
                        st.warning(f"⚠️ **Suspicious Activity**\n\nIP: `{ip}`\n\nEvents: {count}\n\nIntel: {intel}")

        if not threat_found:
             st.success("✅ No critical threats detected in this batch.")

        # Final Summary Table
        st.markdown("### 📊 Threat Report Summary")
        st.table(pd.DataFrame(results))

    else:
        st.write("👈 Click 'Run Threat Hunt' in the sidebar to start.")

if __name__ == "__main__":
    main()