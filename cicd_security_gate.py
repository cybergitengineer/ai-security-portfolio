import streamlit as st
import re

st.set_page_config(page_title="CI/CD Security Gate", page_icon="🚧", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #0f172a; color: #e2e8f0; }
    </style>
    """, unsafe_allow_html=True)

st.title("🚧 CI/CD Security Gate (SAST)")
st.markdown("Simulate a pipeline blocking insecure code commits.")

# --- VULNERABLE CODE SAMPLE ---
default_code = """
def connect_to_db():
    # TODO: remove this before production
    # DEMO ONLY: This is a fake key for demonstration purposes.
    aws_secret_key = "AKIAIOSFODNN7EXAMPLE" 
    print("Connecting...")

def execute_user_command(cmd):
    # This allows remote code execution!
    eval(cmd) 
"""

# --- RULES ENGINE ---
SECURITY_RULES = [
    {"id": "SAST-001", "name": "AWS Access Key Detected", "pattern": r"AKIA[0-9A-Z]{16}", "severity": "CRITICAL"},
    {"id": "SAST-002", "name": "Dangerous Function 'eval()'", "pattern": r"eval\(", "severity": "HIGH"},
    {"id": "SAST-003", "name": "Hardcoded Password", "pattern": r"password\s*=\s*['\"].+['\"]", "severity": "HIGH"}
]

col1, col2 = st.columns(2)

with col1:
    st.subheader("💻 Source Code")
    code_input = st.text_area("Commit Content", default_code, height=300)

with col2:
    st.subheader("🛡️ Pipeline Status")
    
    if st.button("Run Security Pipeline"):
        violations = []
        for rule in SECURITY_RULES:
            matches = re.findall(rule["pattern"], code_input)
            if matches:
                violations.append({"rule": rule["name"], "severity": rule["severity"], "match": matches[0]})
        
        if violations:
            st.error(f"❌ BUILD FAILED: {len(violations)} Violations Found")
            for v in violations:
                st.error(f"[{v['severity']}] {v['rule']}\n\nMatch: `{v['match']}`")
        else:
            st.success("✅ BUILD PASSED")
            st.write("No static analysis findings detected.")