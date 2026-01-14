import json

# --- 1. THE "BAD" DEPLOYMENT (Simulation) ---
# This simulates a developer trying to deploy an insecure app.
insecure_deployment = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": "nginx-frontend",
        "labels": {
            "app": "frontend"
            # MISSING: "CostCenter" label
        }
    },
    "spec": {
        "containers": [
            {
                "name": "nginx",
                "image": "nginx:latest",
                "securityContext": {
                    "runAsUser": 0,  # <--- DANGER: Running as ROOT!
                    "privileged": True # <--- DANGER: Full Admin Access!
                }
            }
        ]
    }
}

# --- 2. THE POLICY ENGINE (OPA Logic) ---
def evaluate_policy(workload):
    violations = []
    
    print(f"🕵️  Scanning Workload: {workload['metadata']['name']}...")
    
    # RULE 1: Enforce Non-Root Users
    # We loop through every container in the pod
    for container in workload['spec']['containers']:
        user_id = container.get('securityContext', {}).get('runAsUser', 0)
        privileged = container.get('securityContext', {}).get('privileged', False)
        
        if user_id == 0:
            violations.append(f"❌ BLOCK: Container '{container['name']}' is running as ROOT (UID 0). Must be UID 1000+.")
            
        if privileged:
            violations.append(f"❌ BLOCK: Container '{container['name']}' is running as PRIVILEGED mode.")

    # RULE 2: Enforce Governance Labels
    labels = workload['metadata'].get('labels', {})
    if "CostCenter" not in labels:
        violations.append("❌ BLOCK: Missing required metadata label: 'CostCenter'.")

    return violations

# --- 3. THE ADMISSION CONTROLLER (Decision) ---
def main():
    print("🛡️  ZERO TRUST ADMISSION CONTROLLER ONLINE")
    print("-" * 50)
    
    # Run the check
    errors = evaluate_policy(insecure_deployment)
    
    if len(errors) > 0:
        print("\n⛔ ADMISSION DENIED! Security Policies Violated:")
        for err in errors:
            print(err)
        print("\n>>> ACTION: Deployment rejected by OPA Gatekeeper.")
    else:
        print("\n✅ ADMISSION ALLOWED. Workload is secure.")

if __name__ == "__main__":
    main()