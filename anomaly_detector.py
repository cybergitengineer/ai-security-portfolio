import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

st.set_page_config(page_title="ML Anomaly Detector", page_icon="🤖", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #0f172a; color: #e2e8f0; }
    </style>
    """, unsafe_allow_html=True)

st.title("🤖 ML-Based Network Anomaly Detection")
st.markdown("Unsupervised Learning (Isolation Forest) to detect C2 beacons and Data Exfiltration.")

# --- SIDEBAR SETTINGS ---
st.sidebar.header("Simulation Settings")
n_normal = st.sidebar.slider("Normal Events", 500, 2000, 1000)
n_attack = st.sidebar.slider("Attack Events", 5, 50, 20)
contamination = st.sidebar.slider("Contamination (Expected %)", 0.01, 0.1, 0.02)

if st.button("🔄 Train Model & Analyze Traffic"):
    with st.spinner("Generating Traffic & Training Isolation Forest..."):
        # 1. GENERATE DATA
        # Normal (Web browsing)
        normal_data = pd.DataFrame({
            'bytes_sent': np.random.normal(2000, 500, n_normal),
            'duration': np.random.normal(5, 2, n_normal),
            'type': 'Normal'
        })
        
        # Attack (Data Exfiltration - High bytes, Long duration)
        attack_data = pd.DataFrame({
            'bytes_sent': np.random.normal(50000, 10000, n_attack),
            'duration': np.random.normal(120, 30, n_attack),
            'type': 'Attack (Simulated)'
        })
        
        df = pd.concat([normal_data, attack_data], ignore_index=True)
        
        # 2. TRAIN MODEL
        features = ['bytes_sent', 'duration']
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(df[features])
        
        model = IsolationForest(contamination=contamination, random_state=42)
        df['anomaly_score'] = model.fit_predict(X_scaled)
        df['prediction'] = df['anomaly_score'].apply(lambda x: 'Anomaly' if x == -1 else 'Normal')
        
        # 3. VISUALIZE
        col1, col2 = st.columns([3, 1])
        
        with col1:
            st.subheader("Network Traffic Clusters")
            fig = px.scatter(
                df, x='duration', y='bytes_sent', 
                color='prediction', 
                symbol='type',
                color_discrete_map={'Normal': '#3b82f6', 'Anomaly': '#ef4444'},
                title="Isolation Forest Decision Boundary"
            )
            fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font={'color': "white"})
            st.plotly_chart(fig, use_container_width=True)
            
        with col2:
            st.subheader("Detection Stats")
            anomalies = df[df['prediction'] == 'Anomaly']
            st.metric("Total Events", len(df))
            st.metric("Anomalies Detected", len(anomalies))
            
            st.write("### Top Flagged IPs")
            st.dataframe(anomalies.head(10), height=300)

else:
    st.info("👈 Adjust settings and click 'Train Model' to start.")