import sys
import os
import logging

# Add backend to sys.path
sys.path.append("g:/backups/本科毕设/workspace/vulhub-manager/backend")

# Configure logging
logging.basicConfig(level=logging.INFO)

try:
    from app.services import aifw_service
    print("[-] Importing aifw_service successful.")
    
    print("[-] Attempting to deploy AIFW...")
    result = aifw_service.deploy_aifw()
    print(f"[*] Result: {result}")

except ImportError as e:
    print(f"[!] ImportError: {e}")
except Exception as e:
    print(f"[!] Exception: {e}")
