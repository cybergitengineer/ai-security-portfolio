import json
import time
from datetime import datetime
import random

# --- 1. THE "MOCK" SPLUNK API ---
# In a real job, this would be a URL like 'https://splunk-instance:8089'
# We simulate the API response so the code runs without a server.
def mock_splunk_api_query(query_str):
    print(f"📡 Connecting to Splunk API...")
    print(f"🔎 Running Search: '{query_str}'")
    time.sleep(1.5) # Fake network delay
    
    # Simulate a JSON response from Splunk
    return [
        {"timestamp": "2024-01-14T10:01:00", "event": "Failed Login", "user": "admin", "src_ip": "192.168.1.5", "status": "401"},
        {"timestamp": "2024-01-14T10:01:02", "event": "Failed Login", "user": "admin", "src_ip": "192.168.1.5", "status": "401"},
        {"timestamp": "2024-01-14T10:01:05", "event": "Failed Login", "user": "root",  "src_ip": "45.33.22.11", "status": "401"}, # <-- ATTACKER
        {"timestamp": "2024-01-14T10:01:06", "event": "Failed Login", "user": "root",  "src_ip": "45.33.22.11", "status": "401"},
        {"timestamp": "2024-01-14T10:01:07", "event": "Failed Login", "user": "root",  "src_ip": "45.33.22.11", "status": "401"},
        {"timestamp": "2024-01-14T10:02:00", "event": "Success Login", "user": "edgar", "src_ip": "10.0.0.5",    "status": "200"}
    ]

# --- 2. THREAT INTEL ENRICHMENT ---
# Simulate checking an IP against a Threat Feed (like VirusTotal)
def check_ip_reputation(ip_address):
    # In real life, this requests.get('https://virustotal.com/api/...')
    known_bad_ips = ["45.33.22.11", "103.4.5.6"]
    
    if ip_address in known_bad_ips:
        return "CRITICAL: Known Botnet Node"
    elif ip_address.startswith("192.168"):
        return "SAFE: Internal Network"
    else:
        return "UNKNOWN"

# --- 3. THE AUTOMATION LOGIC ---
def main():
    print("🛡️  STARTING AUTOMATED THREAT HUNT\n")
    
    # A. Query Splunk
    search_query = 'search index=security event="Failed Login" | stats count by src_ip'
    logs = mock_splunk_api_query(search_query)
    
    print(f"\n📥 Retrieved {len(logs)} logs from Splunk.\n")
    
    # B. Parse & Analyze
    print("⚙️  Parsing logs and enriching IOCs...\n")
    suspicious_ips = {}
    
    for log in logs:
        if log['event'] == "Failed Login":
            ip = log['src_ip']
            # Count the failures
            suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    # C. Threshold & Alert
    print("🚨 ALERT REPORT:")
    print("-" * 60)
    print(f"{'SOURCE IP':<20} | {'FAILURES':<10} | {'THREAT INTEL'}")
    print("-" * 60)
    
    for ip, count in suspicious_ips.items():
        if count >= 3: # Threshold: 3 failed attempts
            # D. Enrich
            intel = check_ip_reputation(ip)
            print(f"{ip:<20} | {count:<10} | {intel}")
            
            if "CRITICAL" in intel:
                print(f"   >>> ACTION: Automating Firewall Block for {ip}...")

if __name__ == "__main__":
    main()