import os
import json
import asyncio
from typing import Dict, Any, List, Optional, AsyncGenerator
from app.services import agent_service, docker_service, aifw_service
from app.services.db_service import save_agent_history
from app.models.schemas import AgentHistoryRecord
from datetime import datetime
import subprocess

async def tool_read_vulhub_context(target: str) -> str:
    """
    Search local Vulhub for a specific CVE or App name to get background context.
    Returns the README content or an error message if not found.
    """
    readme = agent_service.find_vulhub_readme(target)
    if not readme:
        return f"ToolError: No local documentation found for '{target}' in Vulhub."
    return readme[:8000] # Truncate to save context window

async def tool_verify_aifw_status() -> str:
    """
    Checks if the AIFW (AI Firewall) is enabled and returns its current mode/engine.
    Useful for the agent to know if it needs to apply evasion techniques.
    """
    status = aifw_service.get_aifw_status()
    if not status.get("enabled"):
        return "AIFW is DISABLED. Standard attacks should work."
    
    return f"AIFW is ENABLED. Engine: {status.get('engine')}, Mode: {status.get('mode')}. Evasion techniques (e.g., payload mutation, encoding) may be required."

async def tool_execute_attack(script_code: str, target_url: str) -> str:
    """
    Saves the provided Python script to a temporary file and executes it 
    locally against the target. Returns stdout and stderr.
    """
    # Create temp script
    tmp_path = "/tmp/agent_exploit.py"
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(script_code)
    except Exception as e:
        # Fallback for Windows local test environment
        tmp_path = "agent_exploit_tmp.py"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(script_code)

    try:
        # Assuming python is available
        res = subprocess.run(["python", tmp_path], capture_output=True, text=True, timeout=60)
        output = f"Exit Code: {res.returncode}\n"
        if res.stdout: output += f"STDOUT:\n{res.stdout}\n"
        if res.stderr: output += f"STDERR:\n{res.stderr}\n"
        return output
    except Exception as e:
        return f"ToolError: Execution failed: {str(e)}"
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except:
                pass

async def tool_verify_success(target_container_id: Optional[str] = None) -> str:
    """
    Checks if the attack was successful by looking for /tmp/success in the target container.
    If container_id is not provided, we try to guess it from the active nodes.
    """
    if not target_container_id:
        # Try to find a DMZ container to check
        zones = docker_service.fetch_zone_data(include_stopped=False)
        dmz_nodes = zones.get("dmz", [])
        if not dmz_nodes:
            return "ToolError: No target container ID provided, and no DMZ containers found."
        target_container_id = dmz_nodes[0]["id"]

    try:
        # Check if /tmp/success exists
        res = subprocess.run(
            ["docker", "exec", target_container_id, "ls", "/tmp/success"],
            capture_output=True, text=True, timeout=5
        )
        if res.returncode == 0:
            return "VERIFICATION SUCCESS: /tmp/success found. The target is compromised."
        else:
            return "VERIFICATION FAILED: /tmp/success not found."
    except Exception as e:
        return f"ToolError: Verification check failed: {str(e)}"

class AgentState:
    def __init__(self, target: str, target_url: str, api_key: str, base_url: str, model_name: str):
        self.target = target
        self.target_url = target_url
        self.api_key = api_key
        self.base_url = base_url
        self.model_name = model_name
        
        self.readme_content = ""
        self.aifw_status = ""
        self.payload_script = ""
        self.execution_output = ""
        self.verification_result = ""
        self.error = None
        self.recorded_logs = []

class Orchestrator:
    def __init__(self, state: AgentState):
        self.state = state
        
    async def run(self) -> AsyncGenerator[str, None]:
        
        async def _emit(event_type: str, content: str, attempt: Optional[int] = None):
            if event_type in ['log', 'status', 'error']:
                self.state.recorded_logs.append(f"[{event_type.upper()}] {content}")
            
            payload = {'type': event_type, 'content': content}
            if attempt is not None:
                payload['attempt'] = attempt
            return json.dumps(payload)
            
        try:
            yield await _emit('status', 'Initializing Custom Agent Hub...')
            await asyncio.sleep(1)
            
            # 1. Recon Agent
            yield await _emit('log', f'[Recon Agent] Action: Call `tool_read_vulhub_context({self.state.target})`')
            context_result = await tool_read_vulhub_context(self.state.target)
            if "ToolError" in context_result:
                self.state.error = context_result
                yield await _emit('error', context_result)
                yield json.dumps({'type': 'done'})
                return
                
            self.state.readme_content = context_result
            yield await _emit('log', f'[Recon Agent] Observation: Found {len(context_result)} chars of documentation. Passing to Strategy Agent.')
            await asyncio.sleep(1)
            
            # 2. Strategy Agent
            yield await _emit('log', '[Strategy Agent] Action: Call `tool_verify_aifw_status()`')
            aifw_status = await tool_verify_aifw_status()
            self.state.aifw_status = aifw_status
            yield await _emit('log', f'[Strategy Agent] Observation: {aifw_status}')
            await asyncio.sleep(1)
            
            is_aifw_enabled = "ENABLED" in aifw_status
            max_attempts = 3 if is_aifw_enabled else 1
            
            # 2.5 AIFW Bypass Agent — attempt prompt injection before weaponisation
            aifw_bypass_success = False
            if is_aifw_enabled:
                yield await _emit('log', '[AIFW Bypass Agent] AIFW 处于启用状态，尝试通过提示词注入攻击关闭防火墙...')
                try:
                    from app.services.aifw_attack_service import AifwAttackOrchestrator
                    bypass_orch = AifwAttackOrchestrator(
                        target_url=self.state.target_url,
                        strategies=["direct_injection", "role_hijacking"],
                        api_key=self.state.api_key,
                        base_url=self.state.base_url,
                        model_name=self.state.model_name,
                    )
                    async for evt_json in bypass_orch.run():
                        evt = json.loads(evt_json)
                        if evt.get("type") == "log":
                            yield await _emit('log', f'[AIFW Bypass Agent] {evt["content"]}')
                        elif evt.get("type") == "done":
                            results = evt.get("results", [])
                            aifw_bypass_success = any(r.get("success") for r in results)
                except Exception as bypass_err:
                    yield await _emit('log', f'[AIFW Bypass Agent] 绕过尝试失败: {bypass_err}')

                if aifw_bypass_success:
                    yield await _emit('log', '[AIFW Bypass Agent] 提示词注入成功！AIFW 防御已被削弱，切换为普通攻击模式')
                    self.state.aifw_status += " [BYPASS SUCCESS: AIFW defenses weakened via prompt injection]"
                    max_attempts = 1
                else:
                    yield await _emit('log', '[AIFW Bypass Agent] 提示词注入未成功，将使用传统绕过技术继续攻击')
                await asyncio.sleep(1)

            final_markdown_payload = ""

            for attempt in range(max_attempts):
                if max_attempts > 1:
                    yield await _emit('status', f'Attack Attempt {attempt + 1}/{max_attempts}')
                    
                # 3. Weaponizer Agent
                yield await _emit('log', '[Weaponizer Agent] Action: Synthesizing attack script based on context and AIFW status...')
                
                try:
                    payload_script = ""
                    async for chunk in agent_service.generate_payload_multi_agent(
                        readme_content=self.state.readme_content,
                        target_url=self.state.target_url,
                        aifw_status=self.state.aifw_status,
                        api_key=self.state.api_key,
                        base_url=self.state.base_url,
                        model_name=self.state.model_name,
                        attempt=attempt
                    ):
                        payload_script += chunk
                        yield json.dumps({'type': 'payload_chunk', 'content': chunk, 'attempt': attempt + 1})
                        
                    yield json.dumps({'type': 'payload_done', 'attempt': attempt + 1})
                    
                    # Extract python code from the markdown response
                    python_code = ""
                    in_code_block = False
                    for line in payload_script.split('\n'):
                        if line.strip().startswith('```python'):
                            in_code_block = True
                            continue
                        elif line.strip().startswith('```') and in_code_block:
                            in_code_block = False
                            continue
                        
                        if in_code_block:
                            python_code += line + "\n"
                            
                    if not python_code.strip():
                         # Fallback if no code block was found
                         python_code = payload_script
                         
                    self.state.payload_script = python_code
                    
                    if attempt > 0 and final_markdown_payload:
                        final_markdown_payload += f"\n\n---\n\n### Attempt {attempt + 1}\n\n{payload_script}"
                    else:
                        final_markdown_payload = payload_script
                    
                    yield await _emit('log', '[Weaponizer Agent] Observation: Payload generated successfully.')
                    # Output the full markdown payload to the frontend
                    yield json.dumps({'type': 'payload', 'content': payload_script, 'attempt': attempt + 1})
                except asyncio.CancelledError:
                    yield await _emit('error', 'Agent execution was stopped by the user.')
                    yield json.dumps({'type': 'done'})
                    return
                except Exception as e:
                    yield await _emit('error', f'Weaponizer Agent Error: {str(e)}')
                    yield json.dumps({'type': 'done'})
                    return
                    
                await asyncio.sleep(2)
                
                # 4. Execution Agent
                yield await _emit('status', 'Testing Payload Execution (Local Sandbox)')
                yield await _emit('log', '[Execution Agent] Action: Call `tool_execute_attack()`')
                exec_result = await tool_execute_attack(self.state.payload_script, self.state.target_url)
                self.state.execution_output = exec_result
                
                display_res = exec_result[:200] + "..." if len(exec_result) > 200 else exec_result
                display_res = display_res.replace("\n", " | ")
                yield await _emit('log', f'[Execution Agent] Observation: {display_res}')
                await asyncio.sleep(1)
                
                # 5. Reporting Agent
                yield await _emit('log', '[Reporting Agent] Action: Call `tool_verify_success()`')
                verify_result = await tool_verify_success()
                self.state.verification_result = verify_result
                yield await _emit('log', f'[Reporting Agent] Final Observation: {verify_result}')
                
                if "VERIFICATION SUCCESS" in verify_result:
                     yield await _emit('status', 'Attack succeeded!')
                     break
                else:
                     if attempt < max_attempts - 1:
                         yield await _emit('status', 'Attack failed, analyzing failure and mutating payload...')
                         await asyncio.sleep(2)
                     else:
                         yield await _emit('status', 'All attack attempts failed.')

            yield await _emit('status', 'Multi-Agent Attack Chain Completed.')
            
            # **Save History to Database**
            try:
                record = AgentHistoryRecord(
                    timestamp=datetime.now().isoformat(),
                    target_url=self.state.target_url,
                    cve_name=self.state.target,
                    payload_script=final_markdown_payload,
                    logs=self.state.recorded_logs
                )
                save_agent_history(record)
            except Exception as db_err:
                yield await _emit('error', f'Database Save Error: {str(db_err)}')
                
            yield json.dumps({'type': 'done'})
            
        except asyncio.CancelledError:
            yield await _emit('error', 'Agent execution was stopped by the user.')
            yield json.dumps({'type': 'done'})
        except Exception as e:
            yield await _emit('error', f'Agent Crash: {str(e)}')
            yield json.dumps({'type': 'done'})
