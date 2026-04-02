
import requests
import json
import sys

BASE_URL = "http://127.0.0.1:8000/api"

def run():
    # 1. List Attack Chains
    try:
        resp = requests.get(f"{BASE_URL}/attack-chains")
        if resp.status_code != 200:
            print(f"Failed to list attack chains: {resp.status_code} {resp.text}")
            return
        
        chains = resp.json()
        if not chains:
            print("No attack chains found to test.")
            return

        target = chains[0]
        print(f"Targeting: {target['category']}/{target['name']}/{target['filename']}")

        # 2. Get Original Content
        resp = requests.get(f"{BASE_URL}/attack-chains/content", params={
            "category": target["category"],
            "name": target["name"],
            "filename": target["filename"]
        })
        if resp.status_code != 200:
            print(f"Failed to get content: {resp.status_code} {resp.text}")
            return
        
        original_content = resp.json().get("content", "")
        print(f"Original content length: {len(original_content)}")

        # 3. Modify Content
        new_content = original_content + "\n# TEST_EDIT_MARKER"
        resp = requests.post(f"{BASE_URL}/attack-chains/save", json={
            "category": target["category"],
            "name": target["name"],
            "filename": target["filename"],
            "content": new_content
        })
        
        if resp.status_code != 200:
            print(f"Failed to save content: {resp.status_code} {resp.text}")
            return
        
        print("Save successful.")

        # 4. Verify Change by Reading Again
        resp = requests.get(f"{BASE_URL}/attack-chains/content", params={
            "category": target["category"],
            "name": target["name"],
            "filename": target["filename"]
        })
        current_content = resp.json().get("content", "")
        
        if "# TEST_EDIT_MARKER" in current_content:
            print("Verification SUCCESS: Marker found in content.")
        else:
            print("Verification FAILED: Marker not found.")

        # 5. Revert Change
        resp = requests.post(f"{BASE_URL}/attack-chains/save", json={
            "category": target["category"],
            "name": target["name"],
            "filename": target["filename"],
            "content": original_content
        })
        if resp.status_code == 200:
            print("Revert successful.")
        else:
            print(f"Failed to revert: {resp.status_code} {resp.text}")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    run()
