import os
import subprocess
import json
import time
import platform
from threading import Thread, Lock
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query

from app.core.config import logger, VULHUB_ROOT, ATTACK_CHAINS_ROOT, GO_ROOT
from app.models.schemas import (
    VulnInfo, 
    NetworkCreateRequest, 
    NetworkDeleteRequest, 
    ContainerActionRequest, 
    ActionRequest,
    AttackChainPoc,
    AttackChainRunRequest,
    PivotingRequest,
    CompromiseRequest,
    ContainerOnlyRequest,
    ExecuteExploitRequest,
    ShellExecRequest,
    AttackChainSaveRequest
)
from app.services import docker_service
from app.services import aifw_service
import shlex
import sys

router = APIRouter()

START_TASKS: Dict[str, Dict[str, Any]] = {}
START_TASKS_LOCK = Lock()

def _start_task_key(target_path: str) -> str:
    return os.path.abspath(target_path)

def _start_compose_async(target_path: str, task_key: str):
    def _worker():
        try:
            result = docker_service.run_command(["up", "-d"], cwd=target_path)
            if result.returncode == 0:
                state = "success"
                message = result.stdout
                # Auto-add AIFW intercept rules for newly started containers
                try:
                    if aifw_service.is_aifw_enabled():
                        aifw_service.setup_zone_intercept()
                except Exception as e:
                    logger.warning(f"[AIFW] Auto zone intercept after start failed: {e}")
            else:
                state = "failed"
                message = result.stderr or result.stdout
        except Exception as exc:
            state = "failed"
            message = str(exc)

        with START_TASKS_LOCK:
            task = START_TASKS.get(task_key, {})
            task.update({
                "state": state,
                "message": message,
                "finished_at": time.time()
            })
            START_TASKS[task_key] = task

    Thread(target=_worker, daemon=True).start()

@router.get("/vulns", response_model=List[VulnInfo])
def list_vulns():
    vulns = []
    if not os.path.exists(VULHUB_ROOT):
        return []
        
    for app_name in os.listdir(VULHUB_ROOT):
        app_path = os.path.join(VULHUB_ROOT, app_name)
        if not os.path.isdir(app_path) or app_name.startswith('.'):
            continue
            
        for cve_name in os.listdir(app_path):
            cve_path = os.path.join(app_path, cve_name)
            if not os.path.isdir(cve_path):
                continue
                
            if os.path.exists(os.path.join(cve_path, 'docker-compose.yml')):
                relative_path = os.path.relpath(cve_path, VULHUB_ROOT)
                vulns.append(VulnInfo(
                    app=app_name,
                    cve=cve_name,
                    path=relative_path,
                    description=f"Environment for {app_name}/{cve_name}"
                ))
    return vulns

@router.get("/networks")
def get_networks():
    try:
        ls_res = subprocess.run(["docker", "network", "ls", "-q"], capture_output=True, text=True, encoding='utf-8')
        if ls_res.returncode != 0:
            return []
        
        net_ids = ls_res.stdout.strip().splitlines()
        if not net_ids:
            return []

        inspect_res = subprocess.run(["docker", "network", "inspect"] + net_ids, capture_output=True, text=True, encoding='utf-8')
        if inspect_res.returncode != 0:
            return []
            
        networks = []
        data = json.loads(inspect_res.stdout)
        for net in data:
            name = net.get("Name")
            driver = net.get("Driver")
            subnet = ""
            ipam_config = net.get("IPAM", {}).get("Config", [])
            if ipam_config and len(ipam_config) > 0:
                subnet = ipam_config[0].get("Subnet", "")
                
            networks.append({
                "name": name,
                "driver": driver,
                "subnet": subnet,
                "id": net.get("Id")[:12]
            })
        return networks
    except Exception as e:
        logger.error(f"Error getting networks: {e}")
        return []

@router.post("/networks/create_defaults")
def create_default_networks(request: NetworkCreateRequest):
    try:
        docker_service.ensure_networks_exist(request.dmz_subnet, request.db_subnet)
        return {"status": "success", "message": "Networks created/verified successfully"}
    except Exception as e:
        logger.error(f"Error creating networks: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/networks/delete")
def delete_network(request: NetworkDeleteRequest):
    try:
        res = subprocess.run(
            ["docker", "network", "rm", request.name], 
            capture_output=True, text=True, encoding='utf-8'
        )
        
        if res.returncode != 0:
             raise HTTPException(status_code=500, detail=res.stderr or res.stdout)
        return {"status": "success", "message": f"Network {request.name} deleted"}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/zones/containers")
def get_zone_containers(include_stopped: bool = Query(False)):
    data = docker_service.fetch_zone_data(include_stopped=include_stopped)
    return data

@router.post("/containers/action")
def container_action(request: ContainerActionRequest):
    if request.action not in ["start", "stop", "restart"]:
         raise HTTPException(status_code=400, detail="Invalid action")
    
    try:
        res = subprocess.run(
            ["docker", request.action, request.container_id],
            capture_output=True, text=True, encoding='utf-8'
        )
        if res.returncode != 0:
            raise HTTPException(status_code=500, detail=res.stderr)
        
        return {"status": "success", "message": f"Container {request.container_id} {request.action}ed"}
    except Exception as e:
        logger.error(f"Container action failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/vulns/start")
def start_vuln(request: ActionRequest):
    target_path = os.path.join(VULHUB_ROOT, request.path)
    compose_path = os.path.join(target_path, 'docker-compose.yml')
    if not os.path.exists(compose_path):
        raise HTTPException(status_code=404, detail="docker-compose.yml not found")

    docker_service.check_port_conflicts(compose_path)

    if request.zone and request.zone != 'default':
        docker_service.ensure_networks_exist(request.dmz_subnet, request.db_subnet)
        docker_service.generate_override_file(compose_path, request.zone)
    else:
        ov_path = os.path.join(target_path, "docker-compose.override.yml")
        if os.path.exists(ov_path):
            try:
                os.remove(ov_path)
            except: pass

    try:
        task_key = _start_task_key(target_path)
        with START_TASKS_LOCK:
            existing = START_TASKS.get(task_key)
            if existing and existing.get("state") == "starting":
                return {"status": "starting", "message": "Pulling images...", "start_task": dict(existing)}

            START_TASKS[task_key] = {
                "state": "starting",
                "message": "Pulling images...",
                "started_at": time.time()
            }
            task_snapshot = dict(START_TASKS[task_key])

        _start_compose_async(target_path, task_key)
        return {"status": "starting", "message": "Pulling images...", "start_task": task_snapshot}
    except HTTPException as he:
        raise he
    except Exception as e:
        logger.error(f"Error starting environment: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/vulns/stop")
def stop_vuln(request: ActionRequest):
    target_path = os.path.join(VULHUB_ROOT, request.path)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Path not found")

    try:
        result = docker_service.run_command(["down"], cwd=target_path)
        
        if result.returncode != 0:
            raise HTTPException(status_code=500, detail=f"Failed to stop: {result.stderr}")
        task_key = _start_task_key(target_path)
        with START_TASKS_LOCK:
            START_TASKS.pop(task_key, None)
        return {"status": "stopped", "message": result.stdout}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/vulns/status")
def get_status(path: str = Query(...)):
    target_path = os.path.join(VULHUB_ROOT, path)
    if not os.path.exists(target_path):
        raise HTTPException(status_code=404, detail="Path not found")

    try:
        result = docker_service.run_command(["ps", "-q", "-a"], cwd=target_path)
        
        container_ids = result.stdout.strip().splitlines()
        
        if not container_ids:
            start_task = None
            task_key = _start_task_key(target_path)
            with START_TASKS_LOCK:
                task = START_TASKS.get(task_key)
                if task:
                    start_task = {
                        "state": task.get("state"),
                        "message": task.get("message"),
                        "started_at": task.get("started_at"),
                        "finished_at": task.get("finished_at")
                    }
            return {"running": False, "containers": [], "message": "No containers found", "start_task": start_task}

        inspect_result = subprocess.run(
            ["docker", "inspect"] + container_ids,
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore'
        )

        containers_data = []
        any_running = False
        
        if inspect_result.returncode == 0:
            try:
                inspect_data = json.loads(inspect_result.stdout)
                for container in inspect_data:
                    state = container.get("State", {})
                    status = state.get("Status", "unknown")
                    is_running = status == "running"
                    if is_running:
                        any_running = True
                        
                    name = container.get("Name", "").lstrip("/")
                    
                    ports = []
                    port_bindings = container.get("NetworkSettings", {}).get("Ports", {}) or {}
                    for private_port, bindings in port_bindings.items():
                        if bindings:
                            for binding in bindings:
                                host_ip = binding.get("HostIp", "")
                                host_port = binding.get("HostPort", "")
                                if host_ip == "0.0.0.0" or host_ip == "::":
                                    display_ip = "127.0.0.1" 
                                else:
                                    display_ip = host_ip
                                ports.append(f"{display_ip}:{host_port} -> {private_port}")

                    ips = []
                    networks = container.get("NetworkSettings", {}).get("Networks", {})
                    for net_name, net_info in networks.items():
                        ip = net_info.get("IPAddress")
                        if ip:
                            ips.append(f"{net_name}: {ip}")

                    containers_data.append({
                        "name": name,
                        "status": status, 
                        "ports": ports,
                        "ips": ips,
                        "details": state 
                    })
            except json.JSONDecodeError:
                pass

        start_task = None
        task_key = _start_task_key(target_path)
        with START_TASKS_LOCK:
            task = START_TASKS.get(task_key)
            if task:
                start_task = {
                    "state": task.get("state"),
                    "message": task.get("message"),
                    "started_at": task.get("started_at"),
                    "finished_at": task.get("finished_at")
                }
                if task.get("state") == "success" and any_running:
                    START_TASKS.pop(task_key, None)
                    start_task = None

        return {"running": any_running, "containers": containers_data, "start_task": start_task}
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return {"running": False, "error": str(e), "start_task": None}

@router.get("/attack-chains", response_model=List[AttackChainPoc])
def list_attack_chains():
    results = []
    if not os.path.exists(ATTACK_CHAINS_ROOT):
        return []
    
    # Iterate category folders (e.g. RCE, sqli)
    for category in os.listdir(ATTACK_CHAINS_ROOT):
        category_path = os.path.join(ATTACK_CHAINS_ROOT, category)
        if not os.path.isdir(category_path) or category.startswith('.'):
            continue
            
        # Iterate vulnerability folders (e.g. CVE-2024-xxxx)
        for vuln_name in os.listdir(category_path):
            vuln_path = os.path.join(category_path, vuln_name)
            if not os.path.isdir(vuln_path) or vuln_name.startswith('.'):
                continue

            # Look for script files (.py, .go)
            for f in os.listdir(vuln_path):
                if f.endswith('.py') or f.endswith('.go'):
                    results.append(AttackChainPoc(
                        category=category,
                        name=vuln_name,
                        filename=f,
                        content=None 
                    ))
                
    return results

@router.get("/attack-chains/content")
def get_attack_chain_content(category: str, name: str, filename: Optional[str] = None):
    if not os.path.exists(ATTACK_CHAINS_ROOT):
        raise HTTPException(status_code=404, detail="Attack chains root not found")

    target_file = filename if filename else f"{name}.py"
    file_path = os.path.join(ATTACK_CHAINS_ROOT, category, name, target_file)
    
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            content = f.read()
        return {"content": content}
    except Exception as e:
        logger.error(f"Error reading {file_path}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/attack-chains/save")
def save_attack_chain_content(request: AttackChainSaveRequest):
    if not os.path.exists(ATTACK_CHAINS_ROOT):
        raise HTTPException(status_code=404, detail="Attack chains root not found")
        
    target_file = request.filename if request.filename else f"{request.name}.py"
    # Security check: Ensure we don't traverse out of ATTACK_CHAINS_ROOT
    # But since we use os.path.join with category and name which come from user, 
    # and assuming they are safe or strictly controlled, we should be okay.
    # Ideally we should validate that category/name don't contain '..'
    
    if ".." in request.category or ".." in request.name or (request.filename and ".." in request.filename):
         raise HTTPException(status_code=400, detail="Invalid path chemicals")

    file_path = os.path.join(ATTACK_CHAINS_ROOT, request.category, request.name, target_file)
    
    # We allow creating new files if they don't exist? 
    # For now let's assume we are saving EXISTING files as per the requirement "Edit and Save"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    try:
        with open(file_path, 'w', encoding='utf-8', newline='') as f:
            f.write(request.content)
        return {"status": "success", "message": f"Saved {target_file}"}
    except Exception as e:
        logger.error(f"Error saving {file_path}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/attack-chains/run")
def run_attack_chain(request: AttackChainRunRequest):
    if not os.path.exists(ATTACK_CHAINS_ROOT):
         raise HTTPException(status_code=404, detail="Root not found")
         
    # 1. Resolve target file
    script_path = None
    if request.filename:
        # User provided filename
        script_path = os.path.join(ATTACK_CHAINS_ROOT, request.category, request.name, request.filename)
    else:
        # Try finding .py then .go
        py_path = os.path.join(ATTACK_CHAINS_ROOT, request.category, request.name, f"{request.name}.py")
        go_path = os.path.join(ATTACK_CHAINS_ROOT, request.category, request.name, f"{request.name}.go")
        
        if os.path.exists(py_path):
            script_path = py_path
        elif os.path.exists(go_path):
            script_path = go_path
        else:
            # Fallback for checking existence later
            script_path = py_path

    if not os.path.exists(script_path):
        raise HTTPException(status_code=404, detail=f"Script not found: {script_path}")
    
    try:
        cmd_args = shlex.split(request.args) if request.args else []
        
        # 2. Python Execution
        if script_path.endswith('.py'):
            cmd = [sys.executable, script_path] + cmd_args
            cwd = os.path.dirname(script_path)
            res = subprocess.run(
                cmd, 
                cwd=cwd, 
                capture_output=True, 
                text=True, 
                encoding='utf-8',
                errors='ignore',
                timeout=120 
            )
            return {
                "stdout": res.stdout,
                "stderr": res.stderr,
                "returncode": res.returncode
            }

        # 3. Go Execution
        elif script_path.endswith('.go'):
            # Host System Info
            host_os = platform.system().lower() # windows, linux, darwin
            host_arch = platform.machine().lower()

            # Normalize host arch
            if host_arch in ['x86_64', 'amd64']:
                host_arch = 'amd64'
            elif host_arch in ['x86', 'i386', 'i686']:
                host_arch = '386'
            
            # Target Config
            target_os = request.go_os.lower() if request.go_os else host_os
            target_arch = request.go_arch.lower() if request.go_arch else host_arch

            cwd = os.path.dirname(script_path)
            filename_base = os.path.splitext(os.path.basename(script_path))[0]
            
            # Binary Name Construction
            binary_name = filename_base
            if target_os == 'windows':
                binary_name += ".exe"
            
            binary_path = os.path.join(cwd, binary_name)

            # Build Environment
            build_env = os.environ.copy()
            build_env["GOOS"] = target_os
            build_env["GOARCH"] = target_arch
            build_env["CGO_ENABLED"] = "0" # Usually safer for portable builds

            # Handle GOROOT/PATH if configured
            go_exec = "go"
            if GO_ROOT:
                 build_env["GOROOT"] = GO_ROOT
                 go_bin_path = os.path.join(GO_ROOT, "bin") 
                 # Prepend to PATH
                 build_env["PATH"] = go_bin_path + os.pathsep + build_env.get("PATH", "")
                 
                 # Resolving absolute path for 'go' command
                 exe_ext = ".exe" if platform.system().lower() == "windows" else ""
                 candidate_go = os.path.join(go_bin_path, "go" + exe_ext)
                 if os.path.exists(candidate_go):
                     go_exec = candidate_go
            
            build_env["GOWORK"] = "" # Avoid workspace interference

            # -- Step A: Compile --
            build_cmd = [go_exec, "build", "-o", binary_name, script_path]
            
            logger.info(f"Compiling Go PoC: {' '.join(build_cmd)} (GOOS={target_os}, GOARCH={target_arch})")
            
            build_res = subprocess.run(
                build_cmd,
                cwd=cwd,
                env=build_env,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore'
            )

            if build_res.returncode != 0:
                return {
                    "stdout": "",
                    "stderr": f"Go Compilation Failed:\nCommand: {' '.join(build_cmd)}\nError: {build_res.stderr}",
                    "returncode": build_res.returncode
                }

            # -- Step B: Execute (if OS matches) --
            can_execute = (target_os == host_os)
            
            if not can_execute:
                 return {
                    "stdout": f"[INFO] Compilation successful.\n[INFO] Binary created at: {binary_path}\n[INFO] Execution skipped: Target OS ({target_os}) does not match Host OS ({host_os}).",
                    "stderr": "",
                    "returncode": 0
                }

            # Prepare execution command
            exec_binary = f"./{binary_name}" if target_os != 'windows' else binary_name
            # If windows, just filename or full path is fine.
            if target_os == 'windows':
                 exec_cmd = [binary_path] + cmd_args
            else:
                 # Ensure chmod +x
                 try:
                     os.chmod(binary_path, 0o755)
                 except: pass
                 exec_cmd = [binary_path] + cmd_args

            logger.info(f"Executing Go PoC: {' '.join(exec_cmd)}")

            res = subprocess.run(
                exec_cmd,
                cwd=cwd,
                capture_output=True, 
                text=True, 
                encoding='utf-8',
                errors='ignore',
                timeout=120
            )

            return {
                "stdout": res.stdout,
                "stderr": res.stderr,
                "returncode": res.returncode
            }

        else:
             raise HTTPException(status_code=400, detail=f"Unsupported file extension: {script_path}")

    except subprocess.TimeoutExpired:
         return {
            "stdout": "",
            "stderr": "Execution timed out after 120 seconds.",
            "returncode": -1
        }
    except Exception as e:
        logger.error(f"Execution Error: {e}")
        return {
            "stdout": "",
            "stderr": str(e),
            "returncode": -1
        }

@router.post("/attack-chain/pivoting")
def start_pivoting_attack(request: PivotingRequest):
    """
    Start an automated pivoting attack chain from a compromised container.
    If target_container_id is provided, it performs a targeted attack instead of a full scan.
    """
    try:
        logs = docker_service.run_pivoting_attack(request.start_container_id, request.target_container_id)
        return {"status": "finished", "logs": logs}
    except Exception as e:
        import traceback
        logger.error(f"Pivoting failed: {e}")
        logger.error(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/containers/compromise")
def set_container_compromised(request: CompromiseRequest):
    """
    Manually set the compromised status of a container.
    """
    try:
        if request.is_compromised:
            docker_service.mark_as_compromised(request.container_id)
        else:
            # Optional: Add methods to un-compromise if needed, 
            # but currently docker_service only has add().
            # For now we only support adding.
            pass
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error setting compromise status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/containers/verify-compromise")
def verify_compromise(request: ContainerOnlyRequest):
    """
    Checks if /tmp/success exists in the container.
    If yes, marks it as compromised in memory.
    """
    try:
        # Check for success file
        # Using specific command to avoid ambiguity
        check_cmd = "test -f /tmp/success && echo 'YES' || echo 'NO'"
        result = docker_service.exec_container_cmd(request.container_id, check_cmd)
        
        is_pwned = "YES" in result
        
        if is_pwned:
            docker_service.mark_as_compromised(request.container_id)
            return {"status": "success", "compromised": True}
        else:
            return {"status": "success", "compromised": False, "message": "Verification failed: /tmp/success not found"}
            
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        # If container is down or other error
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/attack-chain/scan-result")
def get_pivoting_scan_result(container_id: str):
    """
    Retrieve the content of /tmp/result.txt from the specified container.
    """
    try:
        content = docker_service.exec_container_cmd(container_id, "cat /tmp/result.txt")
        return {"content": content}
    except Exception as e:
        logger.error(f"Failed to get scan result: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/attack-chain/run-local")
def run_local_exploit_endpoint(request: ContainerOnlyRequest):
    """
    Run an exploit script locally against a container (usually External zone).
    """
    try:
        result = docker_service.run_local_exploit(request.container_id)
        return result
    except Exception as e:
        logger.error(f"Local exploit failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/containers/exploit/exec")
def execute_exploit_cmd_custom(request: ExecuteExploitRequest):
    """
    Executes the exploit script for the given container with a custom command/argument.
    """
    try:
        result = docker_service.run_custom_exploit_cmd(request.container_id, request.command_args)
        if result['status'] == 'error':
            raise HTTPException(status_code=500, detail=result['message'])
        return result
    except Exception as e:
         raise HTTPException(status_code=500, detail=str(e))

@router.post("/containers/shell/exec")
def exec_interactive_shell(request: ShellExecRequest):
    """
    Execute a shell command inside a compromised RCE container.
    """
    try:
        pwn_type = docker_service.get_compromise_type(request.container_id)
        if pwn_type != "RCE":
            raise HTTPException(status_code=403, detail="Interactive shell is only available for RCE-compromised containers.")

        cmd = (request.command or "").strip()
        if not cmd:
            raise HTTPException(status_code=400, detail="Command is empty")

        workdir = request.workdir or "/tmp"
        result = docker_service.exec_container_cmd_full(request.container_id, cmd, workdir)
        return result
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

