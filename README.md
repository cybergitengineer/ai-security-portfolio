# AI-Driven Security Engineering Portfolio

## Overview
This repository demonstrates a suite of **Security Automation & AI Engineering** tools designed to modernize Threat Intelligence, SOC Operations, and DevSecOps workflows.

These prototypes were built to solve real-world security challenges, including:
* **Reducing MTTR (Mean Time to Remediate)** using Retrieval-Augmented Generation (RAG).
* **Detecting Zero-Day Attacks** using Unsupervised Machine Learning.
* **Enforcing Zero Trust** via Policy-as-Code.

## 🛠️ The Toolkit

### 1. 🤖 AI Threat Intelligence Analyst (`rag_tool.py`)
**The Problem:** SOC analysts are overwhelmed by the volume of CVE data and threat feeds.
**The Solution:** A RAG (Retrieval-Augmented Generation) pipeline that ingests raw threat data, vectorizes it, and allows analysts to query vulnerabilities using natural language with strict "anti-hallucination" guardrails.
* **Tech Stack:** Python, LangChain, OpenAI (GPT-3.5), ChromaDB.
* **Key Feature:** Uses a "Closed Domain" prompt template to ensure the AI only answers based on verified internal intel.

### 2. 🕵️ Unsupervised Anomaly Detection (`anomaly_detector.py`)
**The Problem:** Traditional signature-based ID/IPS fails to catch novel data exfiltration techniques.
**The Solution:** An ML model using **Isolation Forest** to analyze network traffic patterns. It establishes a baseline of "normal" behavior and automatically flags statistical outliers (e.g., high-byte data dumps) without requiring prior attack signatures.
* **Tech Stack:** Scikit-learn, Pandas, NumPy.
* **Key Feature:** Detects "Data Exfiltration" anomalies in synthesized network logs with >95% accuracy.

### 3. 🛡️ Zero Trust Policy Engine (`policy_engine.py`)
**The Problem:** Developers often deploy insecure containers (e.g., running as Root) into Kubernetes clusters.
**The Solution:** A simulation of a **Kubernetes Admission Controller** (OPA Gatekeeper). It parses deployment YAMLs and enforces policies that block workloads violating security standards before deployment.
* **Tech Stack:** Python (Policy-as-Code logic).
* **Rules Enforced:** Blocks Root users (UID 0) and enforces governance labels (e.g., `CostCenter`).

### 4. 🚨 SOC Automation & Threat Hunting (`splunk_tool.py`)
**The Problem:** Manual log analysis is too slow to stop active attacks.
**The Solution:** An automated threat hunting script that mocks a **Splunk API** connection. It queries login logs, aggregates failure counts, enriches IP addresses with Threat Intelligence, and simulates automated firewall blocking.
* **Tech Stack:** Python, Mock APIs, JSON parsing.
* **Key Feature:** Automates the "Detect -> Enrich -> Respond" loop for Brute Force attacks.

### 5. 🏗️ CI/CD Security Gate (`cicd_security_gate.py`)
**The Problem:** Secrets and dangerous functions often leak into production code.
**The Solution:** A static analysis (SAST) tool designed for CI/CD pipelines. It scans commit diffs for hardcoded AWS keys and dangerous functions (like `eval()`), breaking the build if high-severity issues are found.
* **Tech Stack:** Python, Regex.
* **Key Feature:** Acts as a hard blocking gate in the SDLC.

---

## 🚀 Quick Start

### Prerequisites
* Python 3.10+
* An OpenAI API Key (for the RAG tool)

### Installation
1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YourUsername/ai-security-portfolio.git](https://github.com/YourUsername/ai-security-portfolio.git)
    cd ai-security-portfolio
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure Environment:**
    Create a `.env` file in the root directory:
    ```ini
    OPENAI_API_KEY=sk-your-key-here
    ```

### Running the Tools

**Run the AI Analyst:**
```bash
python rag_tool.py
# Query Suggestion: "What is the remediation for Log4Shell?"