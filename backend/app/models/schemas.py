from typing import List, Optional
from pydantic import BaseModel

class VulnInfo(BaseModel):
    app: str
    cve: str
    path: str
    description: str = ""

class NetworkDeleteRequest(BaseModel):
    name: str

class NetworkCreateRequest(BaseModel):
    dmz_subnet: str
    db_subnet: str

class ContainerActionRequest(BaseModel):
    container_id: str
    action: str # "start", "stop", "restart"

class ActionRequest(BaseModel):
    path: str
    zone: Optional[str] = "default" # "dmz", "intranet", "database", "default"
    dmz_subnet: Optional[str] = "" 
    db_subnet: Optional[str] = ""

class AttackChainPoc(BaseModel):
    category: str
    name: str
    filename: str

class ExecuteExploitRequest(BaseModel):
    container_id: str
    command_args: str
    content: Optional[str] = None

class ShellExecRequest(BaseModel):
    container_id: str
    command: str
    workdir: Optional[str] = "/tmp"

class AttackChainRunRequest(BaseModel):
    category: str
    name: str
    filename: Optional[str] = None
    args: str
    go_os: Optional[str] = None
    go_arch: Optional[str] = None

class AttackChainRunResponse(BaseModel):
    stdout: str
    stderr: str
    returncode: int

class PivotingRequest(BaseModel):
    start_container_id: str
    target_container_id: Optional[str] = None

class CompromiseRequest(BaseModel):
    container_id: str
    is_compromised: bool

class ContainerOnlyRequest(BaseModel):
    container_id: str

# ── AIFW Models ──────────────────────────────────────────────

class AIFWDeployRequest(BaseModel):
    aifw_port: Optional[str] = "9999"
    mode: Optional[str] = "DetectionOnly"  # "DetectionOnly" or "On"
    engine: Optional[str] = None  # "modsecurity" or "waf-brain" or "ml-based-waf"

class AIFWInterceptRequest(BaseModel):
    target_ip: str
    target_port: str

class AIFWConfigRequest(BaseModel):
    llm_api_url: Optional[str] = None
    llm_api_key: Optional[str] = None
    llm_model: Optional[str] = None
    aifw_port: Optional[str] = None
    mode: Optional[str] = None
    engine: Optional[str] = None
    atk_llm_api_url: Optional[str] = None
    atk_llm_api_key: Optional[str] = None
    atk_llm_model: Optional[str] = None

class AIFWAnalyzeRequest(BaseModel):
    log_entries: Optional[List[dict]] = None
    llm_api_url: Optional[str] = None
    llm_api_key: Optional[str] = None
    llm_model: Optional[str] = None

class AttackChainSaveRequest(BaseModel):
    category: str
    name: str
    filename: Optional[str] = None
    content: str

# ── AIFW Attack Agent Models ─────────────────────────────────

class AifwAttackRequest(BaseModel):
    target_url: Optional[str] = None
    strategies: Optional[List[str]] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None
    keep_state: Optional[bool] = True

# ── Agent History Models ──────────────────────────────────────

class AgentHistoryRecord(BaseModel):
    id: Optional[int] = None
    timestamp: str
    target_url: str
    cve_name: str
    payload_script: str
    logs: List[str]

# ── Attack Report Models ──────────────────────────────────────

class AttackReportNode(BaseModel):
    id: str
    name: str
    ip: str
    zone: str
    pwn_type: Optional[str] = None
    cve: Optional[str] = None
    app: Optional[str] = None

class AttackReportEdge(BaseModel):
    sourceId: str
    targetId: str
    status: str  # 'pending' | 'success'

class AttackReportRequest(BaseModel):
    nodes: List[AttackReportNode]
    edges: List[AttackReportEdge]
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None
