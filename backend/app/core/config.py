
import os
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulhub-manager")

# Constants for Multi-level Network
DEFAULT_DMZ_SUBNET = "192.168.6.0/24"
DEFAULT_DB_SUBNET = "192.168.5.0/24"
NET_DMZ_NAME = "vulhub_net_dmz_a"
NET_DB_NAME = "vulhub_net_db_b"

# Configuration
# Assuming backend/app/core/config.py -> root is 3 levels up from app (vulhub-manager/backend/app/core -> backend/app -> backend -> vulhub-manager)
# Wait: 
# __file__ = backend/app/core/config.py
# dirname = backend/app/core
# dirname = backend/app
# dirname = backend
# dirname = vulhub-manager
# dirname = workspace (if vulhub is sibling)

# In original main.py:
# WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# main.py was in backend/main.py. 
# backend/main.py -> backend -> vulhub-manager -> workspace
# So 3 levels up.

# Now config.py is in backend/app/core/config.py
# backend/app/core/config.py -> backend/app/core -> backend/app -> backend -> vulhub-manager -> workspace
# So 5 levels up?
# Let's count dirs.
# 1. os.path.abspath(__file__) -> config.py
# 2. dirname -> core
# 3. dirname -> app
# 4. dirname -> backend
# 5. dirname -> vulhub-manager
# 6. dirname -> workspace (where vulhub probably is effectively 'sibling' to vulhub-manager or inside) 

# Re-read original main.py logic:
# WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# main.py is in backend/
# 1. backend
# 2. vulhub-manager (containing backend)
# 3. workspace (containing vulhub-manager)
# VULHUB_ROOT = join(WORKSPACE_ROOT, "vulhub")

# So if config.py is in backend/app/core/
# 1. core
# 2. app
# 3. backend
# 4. vulhub-manager
# 5. workspace

WORKSPACE_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
VULHUB_ROOT = os.path.join(WORKSPACE_ROOT, "vulhub")

if not os.path.exists(VULHUB_ROOT):
    logger.warning(f"Vulhub root not found at {VULHUB_ROOT}. Please check path.")

ATTACK_CHAINS_ROOT = os.path.join(WORKSPACE_ROOT, "vulhub-manager", "attack-chains")
if not os.path.exists(ATTACK_CHAINS_ROOT):
    logger.warning(f"Attack chains root not found at {ATTACK_CHAINS_ROOT}.")

AIFW_ROOT = os.path.join(WORKSPACE_ROOT, "vulhub-manager", "aifw")
if not os.path.exists(AIFW_ROOT):
    logger.warning(f"AIFW root not found at {AIFW_ROOT}.")
    
# Go Configuration
GO_ROOT = os.getenv("GOROOT", r"F:\Go_1.23.3")

# LLM Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.moonshot.cn/v1")
OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME", "moonshot-v1-8k")
