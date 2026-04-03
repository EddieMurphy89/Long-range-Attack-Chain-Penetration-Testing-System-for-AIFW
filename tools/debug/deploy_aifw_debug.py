import sys
import os
import logging

DEBUG_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(DEBUG_DIR, "..", ".."))
BACKEND_ROOT = os.path.join(PROJECT_ROOT, "backend")

# Add backend to sys.path
sys.path.insert(0, BACKEND_ROOT)

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
