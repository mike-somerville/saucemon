import os
import json
import sys

# Configuration
MANIFEST_FILE = "saucemon-manifest.json"
HOOK_START = "SAUCEMON_HOOK_START"
HOOK_END = "SAUCEMON_HOOK_END"

def load_manifest():
    if not os.path.exists(MANIFEST_FILE):
        print(f"[ERROR] Manifest file '{MANIFEST_FILE}' not found.")
        sys.exit(1)
    with open(MANIFEST_FILE, 'r') as f:
        return json.load(f)

def check_health():
    manifest = load_manifest()
    hooks = manifest.get("hooks", [])
    isolated_files = manifest.get("isolated_files", [])
    
    issues_found = 0
    print(f"\n--- Saucemon Health Check (Project: {manifest.get('project')}) ---")

    # 1. Check Hook Integrity in Base Files
    print(f"\n[Checking Base File Hooks...]")
    for h in hooks:
        file_path = h.get("file")
        hook_name = h.get("hook")
        
        if not os.path.exists(file_path):
            print(f"[FAIL] Missing File: {file_path}")
            issues_found += 1
            continue

        with open(file_path, 'r') as f:
            content = f.read()
            
        if HOOK_START in content and HOOK_END in content:
            if hook_name in content:
                print(f"[OK]   {file_path} -> Hook '{hook_name}' is healthy.")
            else:
                print(f"[WARN] {file_path} -> Hook markers found, but logic '{hook_name}' is missing!")
                issues_found += 1
        else:
            print(f"[CRIT] {file_path} -> HOOK DESTROYED! Markers not found.")
            issues_found += 1

    # 2. Check Isolated Files Existence
    print(f"\n[Checking Isolated Saucemon Files...]")
    for iso_file in isolated_files:
        if os.path.exists(iso_file):
            print(f"[OK]   {iso_file} exists.")
        else:
            print(f"[FAIL] {iso_file} IS MISSING!")
            issues_found += 1

    # Final Report
    print("\n--- Summary ---")
    if issues_found == 0:
        print("[SUCCESS] All Saucemon customizations are intact.")
        sys.exit(0)
    else:
        print(f"[ALERT] Found {issues_found} issue(s). Review the log above before deploying.")
        sys.exit(1)

if __name__ == "__main__":
    check_health()
