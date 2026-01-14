import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

def generate_dummy_data():
    print("📊 Generating network traffic data...")
    # 1. Normal Traffic (Employees browsing web)
    # Small bytes (100-5000), Short duration
    n_normal = 1000
    normal_data = pd.DataFrame({
        'bytes_sent': np.random.normal(2000, 500, n_normal),
        'duration_seconds': np.random.normal(5, 2, n_normal),
        'packet_count': np.random.normal(50, 10, n_normal)
    })

    # 2. Attack Traffic (Data Exfiltration)
    # Massive bytes (50,000+), Long duration
    n_attack = 20
    attack_data = pd.DataFrame({
        'bytes_sent': np.random.normal(50000, 10000, n_attack),
        'duration_seconds': np.random.normal(120, 30, n_attack),
        'packet_count': np.random.normal(2000, 500, n_attack)
    })

    return pd.concat([normal_data, attack_data], ignore_index=True)

def main():
    # 1. Get Data
    df = generate_dummy_data()
    
    # 2. Train Model (Unsupervised - we don't tell it what an attack looks like)
    print("🤖 Training Isolation Forest (Unsupervised)...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(df)
    
    model = IsolationForest(contamination=0.02, random_state=42)
    df['anomaly_score'] = model.fit_predict(X_scaled)

    # 3. Results
    anomalies = df[df['anomaly_score'] == -1] # -1 means Anomaly
    
    print(f"\n✅ Scan Complete.")
    print(f"   Analyzed {len(df)} connections.")
    print(f"   Found {len(anomalies)} suspicious events.\n")
    
    print("🚨 TOP 5 SUSPICIOUS CONNECTIONS DETECTED:")
    print(anomalies.sort_values(by='bytes_sent', ascending=False).head(5).to_string(index=False))

if __name__ == "__main__":
    main()