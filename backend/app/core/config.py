import logging
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("vulhub-manager")

# Constants for Multi-level Network
DEFAULT_DMZ_SUBNET = "192.168.6.0/24"
DEFAULT_DB_SUBNET = "192.168.5.0/24"
NET_DMZ_NAME = "vulhub_net_dmz_a"
NET_DB_NAME = "vulhub_net_db_b"

# Project layout
CONFIG_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_ROOT = os.path.abspath(os.path.join(CONFIG_DIR, "..", ".."))
PROJECT_ROOT = os.path.abspath(os.path.join(BACKEND_ROOT, ".."))
WORKSPACE_ROOT = os.path.dirname(PROJECT_ROOT)

def _resolve_path(env_var_name: str, *candidates: str) -> str:
    override = os.getenv(env_var_name)
    if override:
        return os.path.abspath(override)

    normalized = [os.path.abspath(candidate) for candidate in candidates if candidate]
    for candidate in normalized:
        if os.path.exists(candidate):
            return candidate

    return normalized[0] if normalized else ""

# Resource roots
VULHUB_ROOT = _resolve_path(
    "VULHUB_ROOT",
    os.path.join(PROJECT_ROOT, "vulhub"),
    os.path.join(WORKSPACE_ROOT, "vulhub"),
)
ATTACK_CHAINS_ROOT = _resolve_path("ATTACK_CHAINS_ROOT", os.path.join(PROJECT_ROOT, "attack-chains"))
AIFW_ROOT = _resolve_path("AIFW_ROOT", os.path.join(PROJECT_ROOT, "aifw"))
CHROMA_DB_DIR = _resolve_path("CHROMA_DB_DIR", os.path.join(PROJECT_ROOT, ".chroma_db"))

if not os.path.exists(VULHUB_ROOT):
    logger.warning(f"Vulhub root not found at {VULHUB_ROOT}. Please check path.")

if not os.path.exists(ATTACK_CHAINS_ROOT):
    logger.warning(f"Attack chains root not found at {ATTACK_CHAINS_ROOT}.")

if not os.path.exists(AIFW_ROOT):
    logger.warning(f"AIFW root not found at {AIFW_ROOT}.")

# Go Configuration
# Prefer an explicit GOROOT when provided; otherwise rely on `go` from PATH.
GO_ROOT = os.getenv("GOROOT", r"F:\Go_1.23.3") # r"F:\Go_1.23.3"

# LLM Configuration
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY", "")
OPENAI_BASE_URL = os.getenv("OPENAI_BASE_URL", "https://api.moonshot.cn/v1")
OPENAI_MODEL_NAME = os.getenv("OPENAI_MODEL_NAME", "moonshot-v1-8k")
