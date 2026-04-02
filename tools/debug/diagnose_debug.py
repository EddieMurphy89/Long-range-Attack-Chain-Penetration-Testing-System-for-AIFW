import subprocess
import json
import os
import sys

def run_cmd(cmd):
    try:
        res = subprocess.run(cmd, shell=True, capture_output=True, text=True, encoding='utf-8')
        return res.stdout.strip(), res.stderr.strip(), res.returncode
    except Exception as e:
        return "", str(e), -1

def check_aifw_status():
    print("[-] Checking vulhub-aifw container status...")
    out, err, code = run_cmd("docker inspect --format '{{.State.Status}}' vulhub-aifw")
    if code != 0:
        print(f"    [!] Error/Not Found: {err}")
        return False
    print(f"    [*] Status: {out}")
    return out == "running"

def check_state_file():
    print("[-] Checking backend state file...")
    path = "g:/backups/本科毕设/workspace/vulhub-manager/backend/app/services/aifw_state.json"
    if os.path.exists(path):
        with open(path, 'r', encoding='utf-8') as f:
            print(f"    [*] Content: {f.read()}")
    else:
        print("    [!] State file not found")

def check_iptables():
    print("[-] Checking iptables in aifw...")
    out, err, code = run_cmd("docker exec vulhub-aifw iptables -t nat -L AIFW_INTERCEPT -n -v")
    if code != 0:
        print(f"    [!] Failed: {err}")
    else:
        print(out)

def check_logs():
    print("[-] Checking ModSecurity audit log...")
    out, err, code = run_cmd("docker exec vulhub-aifw tail -n 10 /var/log/modsecurity/audit.log")
    if code != 0:
        print(f"    [!] Failed: {err}")
    else:
        if not out:
            print("    [*] Log is empty")
        else:
            print(out)

def test_request():
    print("[-] Testing request to localhost:10001 (assuming a rule exists)...")
    try:
        import requests
        resp = requests.get("http://localhost:10001", timeout=2)
        print(f"    [*] Response: {resp.status_code}")
    except Exception as e:
        print(f"    [!] Request failed: {e}")

if __name__ == "__main__":
    running = check_aifw_status()
    check_state_file()
    check_iptables()
    check_logs()

    # Load state to find a port to test
    try:
        with open("g:/backups/本科毕设/workspace/vulhub-manager/backend/app/services/aifw_state.json", 'r', encoding='utf-8') as f:
            state = json.load(f)
            rules = state.get("rules", {})
            print(f"[-] Active Rules: {json.dumps(rules, indent=2)}")
            
            # Pick a rule to test. Preferably one that is HTTP.
            # We'll try the first one that looks like it might be HTTP (port 8080 or 3000 etc)
            target_port = None
            for target, port in rules.items():
                if ":8080" in target or ":3000" in target or ":80" in target:
                    target_port = port
                    print(f"    [*] Selected test target: localhost:{port} (maps to {target})")
                    break
            
            if target_port:
                import requests
                url = f"http://127.0.0.1:{target_port}/?id=1' OR '1'='1"
                print(f"[-] Sending attack request to {url}...")
                try:
                    resp = requests.get(url, timeout=5)
                    print(f"    [*] Response Code: {resp.status_code}")
                    if resp.status_code == 403:
                        print("    [+] BLOCKED! ModSecurity is working.")
                    else:
                        print(f"    [?] Not blocked (Status: {resp.status_code}). Check logs.")
                except Exception as e:
                    print(f"    [!] Request failed: {e}")
            else:
                print("    [!] No suitable HTTP rule found to test.")

    except Exception as e:
        print(f"[!] Failed to load state or test: {e}")

