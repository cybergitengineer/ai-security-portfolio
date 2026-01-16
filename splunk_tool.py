import streamlit as st
import time
import pandas as pd

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

# --- 1. THE "MOCK" SPLUNK API ---
def mock_splunk_api_query(query_str):
    with st.spinner(f"📡 Connecting to Splunk API... Running: '{query_str}'"):
        time.sleep(1.5) # Fake network delay
    
    # Simulate a JSON response from Splunk
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
    known_bad_ips = ["45.33.22.11", "103.4.5.6"]
    
    if ip_address in known_bad_ips:
        return "CRITICAL: Known Botnet Node"
    elif ip_address.startswith("192.168"):
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
    event_type = st.sidebar.selectbox("Event Type", ["Failed Login", "Malware Detected", "Data Exfiltration"])
    
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
        
        # Logic to count failures
        for log in logs:
            if log['event'] == "Failed Login":
                ip = log['src_ip']
                suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

        # C. Display Alerts
        cols = st.columns(3)
        
        for ip, count in suspicious_ips.items():
            intel = check_ip_reputation(ip)
            
            # Create a nice result object for the table
            results.append({"Source IP": ip, "Failures": count, "Threat Intel": intel})
            
            # Display Critical Alerts Prominently
            if count >= 3:
                with cols[0]:
                    if "CRITICAL" in intel:
                        st.error(f"🚨 **CRITICAL ALERT**\n\nIP: `{ip}`\n\nFailures: {count}\n\nIntel: {intel}")
                        st.button(f"🔥 Block {ip} on Firewall", key=ip)
                    else:
                        st.warning(f"⚠️ **Suspicious Activity**\n\nIP: `{ip}`\n\nFailures: {count}\n\nIntel: {intel}")

        # Final Summary Table
        st.markdown("### 📊 Threat Report Summary")
        st.table(pd.DataFrame(results))

    else:
        st.write("👈 Click 'Run Threat Hunt' in the sidebar to start.")

if __name__ == "__main__":
    main()