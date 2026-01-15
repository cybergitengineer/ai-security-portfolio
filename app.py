import streamlit as st
import pandas as pd
import numpy as np
import time
import os
from dotenv import load_dotenv
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from langchain_community.document_loaders import TextLoader
from langchain_text_splitters import CharacterTextSplitter
from langchain_openai import OpenAIEmbeddings, ChatOpenAI
from langchain_community.vectorstores import Chroma
from langchain.chains import create_retrieval_chain
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import ChatPromptTemplate

# Load environment variables
load_dotenv()

# --- PAGE CONFIGURATION ---
st.set_page_config(page_title="CyberSec AI Portfolio", page_icon="🛡️", layout="wide")

st.title("🛡️ AI-Driven Security Operations Center")
st.markdown("### Engineered by Edgar | AI Security Engineer")

# --- SIDEBAR NAVIGATION ---
st.sidebar.title("Security Tools")
tool_choice = st.sidebar.radio("Select a Module:", 
    ["🤖 AI Threat Analyst (RAG)", "🕵️ Network Anomaly Detector", "🛡️ Zero Trust Policy Engine"])

# --- TOOL 1: AI THREAT ANALYST ---
if tool_choice == "🤖 AI Threat Analyst (RAG)":
    st.header("🤖 AI Threat Intelligence Analyst")
    st.write("Query the internal CVE knowledge base using natural language.")
    
    # Check for API Key
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        st.error("⚠️ OpenAI API Key is missing! Please set it in Render Environment Variables.")
        st.stop()

    if "history" not in st.session_state:
        st.session_state.history = []

    # Initialize RAG Pipeline (Cached so it doesn't reload every click)
    @st.cache_resource
    def initialize_rag():
        try:
            loader = TextLoader("cve_data.txt")
            documents = loader.load()
            text_splitter = CharacterTextSplitter(chunk_size=1000, chunk_overlap=0)
            texts = text_splitter.split_documents(documents)
            embeddings = OpenAIEmbeddings()
            db = Chroma.from_documents(texts, embeddings)
            retriever = db.as_retriever()
            
            prompt = ChatPromptTemplate.from_template("""
            You are a Cyber Threat Intelligence Analyst. 
            Answer based ONLY on the following context.
            If the answer is not in the context, say "I don't have intel on that."
            <context>{context}</context>
            Question: {input}
            """)
            
            llm = ChatOpenAI(model_name="gpt-3.5-turbo", temperature=0)
            document_chain = create_stuff_documents_chain(llm, prompt)
            retrieval_chain = create_retrieval_chain(retriever, document_chain)
            return retrieval_chain
        except Exception as e:
            return None

    chain = initialize_rag()

    if chain:
        user_input = st.text_input("Ask about a vulnerability (e.g., 'Remediation for Log4Shell'):")
        if st.button("Analyze"):
            with st.spinner("Processing Threat Intel..."):
                try:
                    response = chain.invoke({"input": user_input})
                    st.success(response['answer'])
                    st.session_state.history.append((user_input, response['answer']))
                except Exception as e:
                    st.error(f"Error: {e}")
    else:
        st.warning("⚠️ Could not load CVE Data. Ensure 'cve_data.txt' is in the repo.")

# --- TOOL 2: ANOMALY DETECTOR ---
elif tool_choice == "🕵️ Network Anomaly Detector":
    st.header("🕵️ Unsupervised Anomaly Detection")
    st.write("Detect data exfiltration in synthesized network logs using Isolation Forest.")

    if st.button("Run Live Simulation"):
        # Generate Data
        n_normal = 1000
        n_attack = 20
        normal_data = pd.DataFrame({
            'bytes_sent': np.random.normal(2000, 500, n_normal),
            'packet_count': np.random.normal(50, 10, n_normal),
            'type': 'Normal'
        })
        attack_data = pd.DataFrame({
            'bytes_sent': np.random.normal(50000, 10000, n_attack),
            'packet_count': np.random.normal(2000, 500, n_attack),
            'type': 'Attack (Injected)'
        })
        df = pd.concat([normal_data, attack_data], ignore_index=True)
        
        # Train Model
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(df[['bytes_sent', 'packet_count']])
        model = IsolationForest(contamination=0.02, random_state=42)
        df['anomaly_score'] = model.fit_predict(X_scaled)
        
        anomalies = df[df['anomaly_score'] == -1]
        
        st.subheader("📊 Visualization")
        st.scatter_chart(df, x='packet_count', y='bytes_sent', color='type')
        
        st.subheader(f"🚨 Detected {len(anomalies)} Suspicious Events")
        st.dataframe(anomalies.head(10))

# --- TOOL 3: POLICY ENGINE ---
elif tool_choice == "🛡️ Zero Trust Policy Engine":
    st.header("🛡️ Kubernetes Admission Controller")
    st.write("Simulate OPA Gatekeeper policies against a Deployment YAML.")

    default_yaml = """
    apiVersion: v1
    kind: Pod
    metadata:
      name: nginx-frontend
      labels:
        app: frontend
    spec:
      containers:
      - name: nginx
        image: nginx:latest
        securityContext:
          runAsUser: 0  # <--- Root User!
          privileged: True
    """
    yaml_input = st.text_area("Paste Deployment YAML", default_yaml, height=250)
    
    if st.button("Validate Policy"):
        violations = []
        if "runAsUser: 0" in yaml_input:
            violations.append("❌ BLOCK: Container is running as ROOT (UID 0).")
        if "privileged: True" in yaml_input or "privileged: true" in yaml_input:
            violations.append("❌ BLOCK: Container is running as PRIVILEGED mode.")
        if "CostCenter" not in yaml_input:
            violations.append("❌ BLOCK: Missing required label: 'CostCenter'.")
            
        if violations:
            st.error("⛔ ADMISSION DENIED")
            for v in violations:
                st.write(v)
        else:
            st.success("✅ ADMISSION ALLOWED")