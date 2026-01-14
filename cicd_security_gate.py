import re
import sys

# --- 1. THE "VULNERABLE" CODE TO SCAN ---
# In real life, this would read a file like 'app.py'
# Here, we simulate a developer committing bad code.
vulnerable_code_commit = """
def connect_to_db():
    # TODO: remove this before production
    # DEMO ONLY: This is a fake key for demonstration purposes.
    aws_secret_key = "AKIAIOSFODNN7EXAMPLE"  # <--- VULNERABILITY 1: Hardcoded Secret
    print("Connecting...")

def execute_user_command(cmd):
    # This allows remote code execution!
    eval(cmd)  # <--- VULNERABILITY 2: Dangerous Function
"""

# --- 2. THE SECURITY RULES (Static Analysis) ---
SECURITY_RULES = [
    {
        "id": "SAST-001",
        "name": "Hardcoded AWS Key Detected",
        "pattern": r"AKIA[0-9A-Z]{16}", # Regex for AWS Access Keys
        "severity": "CRITICAL"
    },
    {
        "id": "SAST-002",
        "name": "Dangerous Function 'eval()' Detected",
        "pattern": r"eval\(", 
        "severity": "HIGH"
    },
    {
        "id": "SAST-003",
        "name": "Hardcoded Password",
        "pattern": r"password\s*=\s*['\"].+['\"]",
        "severity": "HIGH"
    }
]

# --- 3. THE PIPELINE RUNNER ---
def run_static_analysis(code_content):
    print("🚀 STARTING CI/CD SECURITY PIPELINE...")
    print("🔍 Step 1: Running Static Analysis (SAST)...")
    
    violations = []
    
    # Check every rule against the code
    for rule in SECURITY_RULES:
        matches = re.findall(rule["pattern"], code_content)
        if matches:
            violations.append({
                "rule": rule["name"],
                "severity": rule["severity"],
                "match": matches[0] # Show the first match
            })

    return violations

def main():
    # Run the scan
    findings = run_static_analysis(vulnerable_code_commit)
    
    # Decide Pass/Fail
    if len(findings) > 0:
        print(f"\n❌ BUILD FAILED: Found {len(findings)} Security Violations!")
        print("-" * 50)
        for f in findings:
            print(f"   [{f['severity']}] {f['rule']}")
            print(f"      Found: '{f['match']}'")
        print("-" * 50)
        print(">>> ACTION: Blocking Merge Request.")
        sys.exit(1) # Return Error Code 1 (Fails the pipeline)
    else:
        print("\n✅ BUILD PASSED: No security issues found.")
        sys.exit(0) # Return Success Code 0

if __name__ == "__main__":
    main()