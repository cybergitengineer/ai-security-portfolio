import streamlit as st
import json

st.set_page_config(page_title="OPA Policy Engine", page_icon="⚖️", layout="wide")

st.markdown("""
    <style>
    .stApp { background-color: #0f172a; color: #e2e8f0; }
    </style>
    """, unsafe_allow_html=True)

st.title("⚖️ Zero Trust Policy Engine (OPA)")
st.markdown("Validate Kubernetes manifests against security policies (Non-Root, Governance, etc).")

# --- DEFAULT INSECURE CONFIG ---
default_manifest = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": "nginx-frontend",
        "labels": {
            "app": "frontend"
            # Missing "CostCenter"
        }
    },
    "spec": {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:latest",
                "securityContext": {
                    "runAsUser": 0,  # Root User (Bad)
                    "privileged": True # Privileged (Bad)
                }
            }
        ]
    }
}

# --- UI LAYOUT ---
col1, col2 = st.columns(2)

with col1:
    st.subheader("📝 Deployment Manifest (JSON)")
    # Allow user to edit the JSON
    json_input = st.text_area("Edit Manifest", json.dumps(default_manifest, indent=4), height=400)

with col2:
    st.subheader("🔍 Policy Audit Results")
    
    if st.button("Run Policy Scan"):
        try:
            workload = json.loads(json_input)
            violations = []
            
            # --- POLICY LOGIC ---
            # 1. Check Root User
            for container in workload.get('spec', {}).get('containers', []):
                sec_ctx = container.get('securityContext', {})
                if sec_ctx.get('runAsUser', 0) == 0:
                    violations.append(f"❌ BLOCK: Container '{container['name']}' running as ROOT (UID 0).")
                if sec_ctx.get('privileged', False):
                    violations.append(f"❌ BLOCK: Container '{container['name']}' is PRIVILEGED.")
            
            # 2. Check Labels
            labels = workload.get('metadata', {}).get('labels', {})
            if "CostCenter" not in labels:
                violations.append("❌ BLOCK: Missing governance label: 'CostCenter'.")
            
            # --- DISPLAY RESULTS ---
            if violations:
                st.error("⛔ ADMISSION DENIED")
                for v in violations:
                    st.write(v)
            else:
                st.success("✅ ADMISSION ALLOWED")
                st.write("Workload complies with all security policies.")
                
        except json.JSONDecodeError:
            st.error("Invalid JSON format. Please check syntax.")