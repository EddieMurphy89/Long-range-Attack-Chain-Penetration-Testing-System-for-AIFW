"""
AIFW API Endpoints
Routes for deploying, managing, and analyzing the AIFW transparent gateway.
"""
from fastapi import APIRouter, HTTPException
from typing import Optional
from app.models.schemas import AIFWDeployRequest, AIFWConfigRequest, AIFWAnalyzeRequest, AIFWInterceptRequest
from app.services import aifw_service
from app.services import aifw_attack_service

router = APIRouter()


@router.post("/aifw/deploy")
async def deploy_aifw(request: Optional[AIFWDeployRequest] = None):
    """Deploy (build + start) the AIFW gateway container."""
    try:
        # If config is provided in deploy request, update it first
        if request:
            config_update = {}
            if request.mode:
                config_update["mode"] = request.mode
            if request.aifw_port:
                config_update["aifw_port"] = request.aifw_port
            if getattr(request, "engine", None):
                config_update["engine"] = request.engine
            
            if config_update:
                aifw_service.update_config(config_update)

        result = aifw_service.deploy_aifw()
        if result["status"] == "error":
            # Return error as JSON, don't raise 500 which might trigger default HTML error page
             return {"status": "error", "message": result.get("message", "Unknown error")}
        return result
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": f"Unhandled exception: {str(e)}"}


@router.post("/aifw/stop")
async def stop_aifw():
    """Stop the AIFW gateway container."""
    result = aifw_service.stop_aifw()
    if result["status"] == "error":
        raise HTTPException(status_code=500, detail=result["message"])
    return result


@router.get("/aifw/status")
async def get_aifw_status():
    """Get AIFW container status and intercept rules."""
    return aifw_service.get_aifw_status()


@router.post("/aifw/intercept")
async def add_intercept(request: AIFWInterceptRequest):
    """Add a dynamic intercept rule for a specific target."""
    if not request.target_ip or not request.target_port:
        raise HTTPException(status_code=400, detail="target_ip and target_port are required")
    result = aifw_service.add_intercept_rule(request.target_ip, request.target_port)
    return result


@router.delete("/aifw/intercept")
async def remove_intercept(target_ip: str, target_port: str):
    """Remove an intercept rule."""
    return aifw_service.remove_intercept_rule(target_ip, target_port)


@router.get("/aifw/intercept/rules")
async def get_intercept_rules():
    """List all active intercept rules."""
    return {"rules": aifw_service.get_intercept_rules()}


@router.post("/aifw/routing/setup")
async def setup_routing():
    """Set up routing for all running Vulhub containers to use AIFW gateway."""
    result = aifw_service.setup_all_container_routing()
    return result


@router.post("/aifw/intercept/zone")
async def setup_zone_intercept():
    """Scan all running containers in all zones and add intercept rules for each.
    This provides zone-level interception — all containers' traffic will be analyzed."""
    result = aifw_service.setup_zone_intercept()
    return result



@router.get("/aifw/logs")
async def get_aifw_logs(tail: int = 200):
    """Read ModSecurity audit logs from the container."""
    return aifw_service.get_aifw_logs(tail=tail)


@router.post("/aifw/logs/clear")
async def clear_aifw_logs():
    """Clear the ModSecurity audit logs."""
    return aifw_service.clear_aifw_logs()


@router.post("/aifw/analyze")
async def analyze_logs(request: AIFWAnalyzeRequest):
    """Send log entries to an LLM for semantic analysis."""
    entries = request.log_entries
    if not entries:
        logs = aifw_service.get_aifw_logs(tail=100)
        entries = logs.get("entries", [])
    if not entries:
        return {"status": "error", "message": "No log entries to analyze"}

    result = await aifw_service.analyze_with_llm(
        log_entries=entries,
        llm_api_url=request.llm_api_url or "",
        llm_api_key=request.llm_api_key or "",
        llm_model=request.llm_model or "",
    )
    return result


@router.post("/aifw/agent-analyze")
async def agent_analyze_logs(request: AIFWAnalyzeRequest):
    """LLM Controller Agent: analyse logs AND execute any ACTION directives
    the LLM outputs. This is the endpoint that is vulnerable to prompt
    injection — crafted payloads in audit logs can trick the LLM into
    disabling the firewall."""
    entries = request.log_entries
    if not entries:
        logs = aifw_service.get_aifw_logs(tail=100)
        entries = logs.get("entries", [])
    if not entries:
        return {"status": "error", "message": "No log entries to analyze"}

    result = await aifw_service.analyze_with_agent(
        log_entries=entries,
        llm_api_url=request.llm_api_url or "",
        llm_api_key=request.llm_api_key or "",
        llm_model=request.llm_model or "",
    )
    return result


@router.post("/aifw/config")
async def update_config(request: AIFWConfigRequest):
    """Update AIFW configuration (LLM settings, etc.)."""
    config_dict = {}
    for field in ["llm_api_url", "llm_api_key", "llm_model", "aifw_port", "mode", "engine",
                   "atk_llm_api_url", "atk_llm_api_key", "atk_llm_model"]:
        val = getattr(request, field, None)
        if val is not None:
            config_dict[field] = val
    return aifw_service.update_config(config_dict)


@router.get("/aifw/config")
async def get_config():
    """Get current AIFW configuration (API key masked)."""
    return aifw_service.get_config()


@router.post("/aifw/config/test")
async def test_config():
    """Test LLM connectivity and ModSecurity container control."""
    return await aifw_service.test_controller_config()


@router.post("/aifw/config/test-attack")
async def test_attack_config(api_url: str = "", api_key: str = "", model: str = ""):
    """Test attack LLM connectivity with provided credentials."""
    return await aifw_service.test_attack_llm(api_url, api_key, model)


@router.get("/aifw/controller/logs")
async def get_controller_logs():
    """Get Controller Agent activity logs."""
    return {"logs": aifw_service.get_controller_logs()}


@router.post("/aifw/controller/logs/clear")
async def clear_controller_logs():
    """Clear Controller Agent activity logs."""
    aifw_service.clear_controller_logs()
    return {"status": "success"}


@router.get("/aifw/attack/state")
async def get_attack_state():
    """Poll attack agent log buffer, status, and results."""
    return aifw_attack_service.get_attack_state()


@router.post("/aifw/attack/cancel")
async def cancel_attack():
    """Signal the running attack to stop."""
    aifw_attack_service.cancel_attack()
    return {"status": "success"}

@router.post("/aifw/attack/logs/clear")
async def clear_attack_logs():
    """Clear attack agent logs."""
    aifw_attack_service.clear_attack_logs()
    return {"status": "success"}


@router.post("/aifw/agent/toggle")
async def toggle_agent(enabled: bool = True):
    """Enable or disable the LLM Controller Agent's ability to execute actions."""
    aifw_service.AIFW_CONFIG["agent_enabled"] = enabled
    aifw_service.save_state()
    return {"status": "success", "agent_enabled": enabled}
