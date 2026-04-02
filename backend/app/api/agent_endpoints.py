from fastapi import APIRouter, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import json
import asyncio
from typing import Optional
from app.services import agent_service, multi_agent_service, report_service
from app.services.db_service import get_agent_history
from app.models.schemas import AttackReportRequest, AifwAttackRequest
from app.services.aifw_attack_service import AifwAttackOrchestrator, ATTACK_STRATEGIES
from app.core import config

router = APIRouter()

class GeneratePayloadRequest(BaseModel):
    target: str # e.g., "CVE-2017-10271" or "weblogic"
    target_url: Optional[str] = "http://localhost:8080"
    api_key: Optional[str] = None
    base_url: Optional[str] = None
    model_name: Optional[str] = None

class AgentConfigRequest(BaseModel):
    api_key: str
    base_url: str
    model_name: str

# In-memory configuration override (for simplicity, could be saved to a file/db)
_agent_config = {
    "api_key": config.OPENAI_API_KEY,
    "base_url": config.OPENAI_BASE_URL,
    "model_name": config.OPENAI_MODEL_NAME
}

@router.get("/agent/config")
def get_agent_config():
    # Return masked key for security
    masked_key = _agent_config["api_key"]
    if masked_key and len(masked_key) > 8:
        masked_key = masked_key[:4] + "..." + masked_key[-4:]
    elif masked_key:
        masked_key = "***"
        
    return {
        "status": "success",
        "api_key": masked_key,
        "base_url": _agent_config["base_url"],
        "model_name": _agent_config["model_name"]
    }

@router.post("/agent/config")
def set_agent_config(request: AgentConfigRequest):
    # Only update if a real key is provided (not masked)
    if request.api_key and not request.api_key.startswith("***") and "..." not in request.api_key:
        _agent_config["api_key"] = request.api_key
        
    if request.base_url:
        _agent_config["base_url"] = request.base_url
        
    if request.model_name:
        _agent_config["model_name"] = request.model_name
        
    return {"status": "success", "message": "Agent configuration updated."}

@router.post("/agent/generate")
async def generate_payload(request: GeneratePayloadRequest):
    # Determine which API credentials to use
    api_key = request.api_key or _agent_config["api_key"]
    base_url = request.base_url or _agent_config["base_url"]
    model_name = request.model_name or _agent_config["model_name"]
    
    if not api_key:
        raise HTTPException(status_code=400, detail="API Key is required to use the AI Agent. Please configure it in the settings.")
        
    state = multi_agent_service.AgentState(
        target=request.target,
        target_url=request.target_url,
        api_key=api_key,
        base_url=base_url,
        model_name=model_name
    )
    
    orchestrator = multi_agent_service.Orchestrator(state)

    async def event_generator():
        async for msg in orchestrator.run():
            yield f"data: {msg}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.post("/agent/aifw-attack")
async def aifw_attack(request: AifwAttackRequest):
    """Launch AIFW prompt-injection attack agent as a background task."""
    from app.services.aifw_attack_service import ATTACK_RUNNING

    if ATTACK_RUNNING:
        raise HTTPException(status_code=409, detail="An attack is already running.")

    api_key = request.api_key or _agent_config["api_key"]
    base_url = request.base_url or _agent_config["base_url"]
    model_name = request.model_name or _agent_config["model_name"]

    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="API Key is required for the AIFW Attack Agent.",
        )

    orchestrator = AifwAttackOrchestrator(
        target_url=request.target_url or "",
        strategies=request.strategies,
        api_key=api_key,
        base_url=base_url,
        model_name=model_name,
        keep_state=request.keep_state if request.keep_state is not None else True,
    )

    async def _run_attack_background():
        try:
            async for _ in orchestrator.run():
                pass
        except Exception as e:
            from app.core.config import logger as _logger
            _logger.error(f"[AIFW-Attack] Background task error: {e}")

    asyncio.create_task(_run_attack_background())
    return {"status": "success", "message": "Attack launched in background. Poll /api/aifw/attack/state for progress."}


@router.get("/agent/aifw-attack/strategies")
def list_aifw_attack_strategies():
    """Return available AIFW attack strategies."""
    return {
        "status": "success",
        "strategies": {
            k: {"name": v["name"], "description": v["description"]}
            for k, v in ATTACK_STRATEGIES.items()
        },
    }


@router.get("/agent/history")
def fetch_agent_history():
    records = get_agent_history()
    return {"status": "success", "data": [r.model_dump() for r in records]}

@router.post("/agent/attack-report")
async def generate_attack_report(request: AttackReportRequest):
    """
    Generate a comprehensive attack chain report using LLM.
    Accepts compromised nodes and attack edges from the frontend,
    returns a streaming Markdown report via SSE.
    """
    # Prefer request-level credentials, fallback to global config
    api_key = request.api_key or _agent_config["api_key"]
    base_url = request.base_url or _agent_config["base_url"]
    model_name = request.model_name or _agent_config["model_name"]

    if not api_key:
        raise HTTPException(
            status_code=400,
            detail="API Key is required. Please enter it in the report dialog."
        )

    # Convert Pydantic models to dicts for the service
    nodes_data = [n.model_dump() for n in request.nodes]
    edges_data = [e.model_dump() for e in request.edges]

    async def event_generator():
        async for msg in report_service.generate_attack_report(
            nodes=nodes_data,
            edges=edges_data,
            api_key=api_key,
            base_url=base_url,
            model_name=model_name,
        ):
            yield f"data: {msg}\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@router.get("/agent/attack-report/history")
def list_attack_report_history():
    """List all saved attack reports in targetzone_history directory."""
    import os
    history_dir = "targetzone_history"
    if not os.path.exists(history_dir):
        return {"status": "success", "data": []}
        
    reports = []
    for filename in os.listdir(history_dir):
        if filename.endswith(".md"):
            filepath = os.path.join(history_dir, filename)
            stat = os.stat(filepath)
            reports.append({
                "filename": filename,
                "size_bytes": stat.st_size,
                "created_at": stat.st_ctime
            })
            
    # Sort by newest first
    reports.sort(key=lambda x: x["created_at"], reverse=True)
    return {"status": "success", "data": reports}

@router.get("/agent/attack-report/history/{filename}")
def read_attack_report_history(filename: str):
    """Read the content of a specific attack report."""
    import os
    # Basic path traversal protection
    if "/" in filename or "\\" in filename or ".." in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
        
    filepath = os.path.join("targetzone_history", filename)
    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")
        
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            content = f.read()
        return {"status": "success", "data": {"filename": filename, "content": content}}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
