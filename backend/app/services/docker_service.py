import os
import sys
import subprocess
import json
import yaml
import re
import shlex
import time
from typing import List, Optional, Dict, Any, Set
from fastapi import HTTPException

from app.core.config import (
    logger, 
    DEFAULT_DMZ_SUBNET, 
    DEFAULT_DB_SUBNET, 
    NET_DMZ_NAME, 
    NET_DB_NAME,
    ATTACK_CHAINS_ROOT,
    VULHUB_ROOT
)
from app.services import aifw_service

FINAL_COMPOSE_CMD = []

# Store compromised container IDs (in-memory)
COMPROMISED_CONTAINERS: Dict[str, str] = {}

def normalize_docker_status(status: str) -> str:
    """Normalize docker status string to a canonical value."""
    if not status:
        return "unknown"

    s = status.strip().lower()

    # docker ps: "Up 5 minutes", "Up 2 hours (Paused)", "Restarting (1) ..."
    if s.startswith("up"):
        if "paused" in s:
            return "paused"
        if "restarting" in s:
            return "restarting"
        return "running"

    # docker ps -a: "Exited (0) 2 minutes ago", "Created", "Dead"
    if s.startswith("exited"):
        return "exited"
    if s.startswith("created"):
        return "created"
    if s.startswith("paused"):
        return "paused"
    if s.startswith("restarting"):
        return "restarting"
    if s.startswith("dead"):
        return "dead"
    if s.startswith("removal") or s.startswith("removed"):
        return "removed"

    # docker inspect state.status already returns canonical values
    if s in {"running", "exited", "paused", "restarting", "dead", "created", "removing"}:
        return s

    # Fallback: take first token
    return s.split(" ")[0]

def get_docker_compose_cmd():
    """Determine whether to use 'docker-compose' or 'docker compose'"""
    global FINAL_COMPOSE_CMD
    if FINAL_COMPOSE_CMD:
        return FINAL_COMPOSE_CMD
    
    # Try 'docker compose' (v2) first
    try:
        ver = subprocess.run(["docker", "compose", "version"], capture_output=True)
        if ver.returncode == 0:
            FINAL_COMPOSE_CMD = ["docker", "compose"]
            logger.info("Using 'docker compose'")
            return FINAL_COMPOSE_CMD
    except FileNotFoundError:
        pass

    # Try 'docker-compose' (v1)
    try:
        ver = subprocess.run(["docker-compose", "--version"], capture_output=True)
        if ver.returncode == 0:
            FINAL_COMPOSE_CMD = ["docker-compose"]
            logger.info("Using 'docker-compose'")
            return FINAL_COMPOSE_CMD
    except FileNotFoundError:
        pass
    
    # Default fallback
    logger.warning("Could not detect docker compose version, defaulting to 'docker-compose'")
    FINAL_COMPOSE_CMD = ["docker-compose"]
    return FINAL_COMPOSE_CMD

def run_command(cmd_args: List[str], cwd: str) -> subprocess.CompletedProcess:
    """Helper to run command and log output"""
    base_cmd = get_docker_compose_cmd()
    full_cmd = base_cmd + cmd_args
    
    # Use absolute path for reliability
    if not os.path.isabs(cwd):
        cwd = os.path.abspath(cwd)

    logger.info(f"Executing: {' '.join(full_cmd)} in {cwd}")
    try:
        result = subprocess.run(
            full_cmd, 
            cwd=cwd, 
            capture_output=True, 
            text=True,
            encoding='utf-8', 
            errors='ignore'
        )
        if result.returncode != 0:
            logger.error(f"Command failed code={result.returncode}")
            logger.error(f"STDOUT: {result.stdout}")
            logger.error(f"STDERR: {result.stderr}")
        return result
    except FileNotFoundError as e:
        logger.error(f"Command not found: {e}")
        return subprocess.CompletedProcess(args=full_cmd, returncode=127, stderr=str(e))

def ensure_networks_exist(dmz_subnet: str = DEFAULT_DMZ_SUBNET, db_subnet: str = DEFAULT_DB_SUBNET):
    """Ensure that the required Docker networks exist."""
    # Use defaults if empty strings provided
    if not dmz_subnet: dmz_subnet = DEFAULT_DMZ_SUBNET
    if not db_subnet: db_subnet = DEFAULT_DB_SUBNET

    networks = {
        NET_DMZ_NAME: dmz_subnet,
        NET_DB_NAME: db_subnet
    }
    
    try:
        res = subprocess.run(
            ["docker", "network", "ls", "--format", "{{.Name}}"], 
            capture_output=True, text=True, encoding='utf-8', errors='ignore'
        )
        existing_networks = res.stdout.splitlines()
    except Exception as e:
        logger.error(f"Failed to list networks: {e}")
        return

    for net_name, subnet in networks.items():
        if net_name not in existing_networks:
            logger.info(f"Creating network {net_name} with subnet {subnet}")
            subnet_cmd = ["docker", "network", "create", "--driver", "bridge", "--subnet", subnet, net_name]
            try:
                res = subprocess.run(subnet_cmd, capture_output=True, text=True, encoding='utf-8')
                if res.returncode != 0:
                    logger.error(f"Failed to create network {net_name}: {res.stderr}")
                else:
                    logger.info(f"Network {net_name} created successfully.")
            except Exception as e:
                logger.error(f"Error creating network: {e}")

def get_used_host_ports_map() -> Dict[int, str]:
    """Get map of currently used host ports to container IDs."""
    try:
        res = subprocess.run(
            ["docker", "ps", "--format", "{{.ID}}|{{.Ports}}"], 
            capture_output=True, text=True, encoding='utf-8', errors='ignore'
        )
    except Exception as e:
        logger.error(f"Error checking docker ps: {e}")
        return {}

    used_ports = {}
    if res.returncode == 0:
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line: continue
            parts = line.split('|')
            if len(parts) < 2: continue
            
            cid = parts[0]
            ports_str = parts[1]
            
            # Example: 0.0.0.0:80->80/tcp
            port_entries = ports_str.split(',')
            for part in port_entries:
                if '->' in part:
                    host_part = part.split('->')[0]
                    if ':' in host_part:
                        try:
                            port_str = host_part.split(':')[-1].strip()
                            used_ports[int(port_str)] = cid
                        except ValueError:
                            pass
    return used_ports

def check_port_conflicts(compose_path: str):
    """Check if ports in docker-compose.yml conflict with running containers."""
    try:
        with open(compose_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Failed to parse compose file: {e}")
        return 
        
    services = data.get('services', {})
    required_ports = []
    
    for service_config in services.values():
        ports = service_config.get('ports', [])
        for port_mapping in ports:
            if isinstance(port_mapping, str):
                if ':' in port_mapping:
                    parts = port_mapping.split(':')
                    try:
                        idx = 1 if len(parts) >= 3 else 0
                        host_port = int(parts[idx])
                        required_ports.append(host_port)
                    except (ValueError, IndexError):
                        pass

    if not required_ports:
        return

    used_ports_map = get_used_host_ports_map()
    
    # Identify container IDs belonging to the current project
    current_project_containers = set()
    try:
        cwd = os.path.dirname(os.path.abspath(compose_path))
        base_cmd = get_docker_compose_cmd()
        # docker-compose ps -q returns IDs of containers for this project
        res = subprocess.run(
            base_cmd + ["ps", "-q"],
            cwd=cwd,
            capture_output=True, text=True, encoding='utf-8', errors='ignore'
        )
        if res.returncode == 0:
            current_project_containers = set(line.strip() for line in res.stdout.splitlines() if line.strip())
    except Exception as e:
        logger.warning(f"Failed to determine current project containers: {e}")

    conflicts = set()
    for p in required_ports:
        if p in used_ports_map:
            owner_id = used_ports_map[p]
            # Check if owner_id matches any current container (prefix match)
            is_owned = False
            for c in current_project_containers:
                if c.startswith(owner_id) or owner_id.startswith(c):
                    is_owned = True
                    break
            
            if not is_owned:
                conflicts.add(p)
    
    if conflicts:
        raise HTTPException(
            status_code=409, 
            detail=f"端口冲突! 端口 {conflicts} 已被其他容器占用. 请先停止冲突容器."
        )

def generate_override_file(compose_path: str, zone: str) -> Optional[str]:
    """Generates a docker-compose.override.yml for the specific zone network configuration."""
    override_path = os.path.join(os.path.dirname(compose_path), "docker-compose.override.yml")
    
    try:
        with open(compose_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
    except:
        return None
        
    services = data.get('services', {}).keys()
    
    networks_config = {}
    networks_to_use = []
    
    if zone == 'dmz':
        networks_config[NET_DMZ_NAME] = {'external': True}
        networks_to_use = [NET_DMZ_NAME]
    elif zone == 'external':
        networks_config[NET_DMZ_NAME] = {'external': True}
        networks_to_use = [NET_DMZ_NAME]
    elif zone == 'database':
        networks_config[NET_DB_NAME] = {'external': True}
        networks_to_use = [NET_DB_NAME]
    elif zone == 'intranet':
        networks_config[NET_DMZ_NAME] = {'external': True}
        networks_config[NET_DB_NAME] = {'external': True}
        networks_to_use = [NET_DMZ_NAME, NET_DB_NAME]
    else:
        if os.path.exists(override_path):
            try:
                os.remove(override_path)
            except: 
                pass
        return None

    override_data = {
        'version': str(data.get('version', '2')),
        'services': {},
        'networks': networks_config
    }
    
    for s in services:
        service_def = {
            'networks': networks_to_use
        }
        # Inject label for External Zone
        if zone == 'external':
            service_def['labels'] = {'com.vulhub.zone': 'external'}
            
        override_data['services'][s] = service_def
        
    try:
        with open(override_path, 'w', encoding='utf-8') as f:
            yaml.dump(override_data, f)
        return override_path
    except Exception as e:
        logger.error(f"Failed to write override file: {e}")
        return None

def fetch_zone_data(include_stopped: bool = False):
    zones = {
        "external": [],
        "dmz": [],
        "database": [],
        "intranet": [],
        "aifw": []
    }
    
    try:
        networks = [NET_DMZ_NAME, NET_DB_NAME]
        container_map = {} 
        
        # 1. Get containers (running only by default)
        # Updated to fetch label for working dir and zone label
        ps_cmd = ["docker", "ps"]
        if include_stopped:
            ps_cmd.append("-a")
        ps_cmd += ["--format", "{{.ID}}|{{.Names}}|{{.Status}}|{{.Ports}}|{{.Label \"com.docker.compose.project.working_dir\"}}|{{.Label \"com.vulhub.zone\"}}"]
        ps_res = subprocess.run(ps_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
        
        if ps_res.returncode == 0:
            for line in ps_res.stdout.splitlines():
                if not line.strip(): continue
                parts = line.split("|")
                if len(parts) >= 3:
                    cid = parts[0]
                    cname = parts[1]
                    status_raw = parts[2]
                    status = normalize_docker_status(status_raw)
                    ports_str = parts[3] if len(parts) > 3 else ""
                    working_dir = parts[4] if len(parts) > 4 else ""
                    zone_label = parts[5] if len(parts) > 5 else ""
                    
                    container_map[cid] = {
                        "id": cid,
                        "name": cname,
                        "status": status,
                        "status_raw": status_raw,
                        "ports": [p.strip() for p in ports_str.split(',')] if ports_str else [],
                        "networks": set(),
                        "ip": "",
                        "ips": [],
                        "working_dir": working_dir,
                        "zone_label": zone_label,
                        "is_compromised": cid in COMPROMISED_CONTAINERS,
                        "pwn_type": COMPROMISED_CONTAINERS.get(cid)
                    }

        # 2. Inspect networks to assign zones
        for net in networks:
            res = subprocess.run(
                ["docker", "network", "inspect", net],
                capture_output=True, text=True, encoding='utf-8', errors='ignore'
            )
            if res.returncode == 0:
                try:
                    net_info = json.loads(res.stdout)
                    if net_info and len(net_info) > 0:
                        containers = net_info[0].get('Containers', {})
                        for cid, info in containers.items():
                             matched_key = None
                             for key in container_map:
                                 if cid.startswith(key):
                                     matched_key = key
                                     break
                             
                             if matched_key:
                                 container_map[matched_key]['networks'].add(net)
                                 ipv4 = info.get('IPv4Address', '').split('/')[0]
                                 container_map[matched_key]['ip'] = ipv4 # Legacy single IP
                                 container_map[matched_key]['ips'].append(ipv4)
                except json.JSONDecodeError:
                    pass

        # 3. Categorize
        zone_cache: Dict[str, Optional[str]] = {}
        for cid, info in container_map.items():
            nets = info['networks']
            is_dmz = NET_DMZ_NAME in nets
            is_db = NET_DB_NAME in nets
            
            # Use all discovered IPs for display
            display_ip = ",".join(list(set(info['ips']))) if info['ips'] else info['ip']

            node = {
                "id": info['id'],
                "name": info['name'],
                "ip": display_ip,
                "ports": info['ports'],
                "status": info['status'],
                "status_raw": info.get('status_raw', info['status']),
                "zone": "unknown",
                "is_compromised": info['is_compromised'],
                "pwn_type": info.get('pwn_type'),
                "cve_info": _extract_cve_from_path(info['working_dir'])
            }

            # Check for AIFW container first
            if info['name'] == "vulhub-aifw" or "vulhub-aifw" in info['name']:
                node['zone'] = 'aifw'
                zones['aifw'].append(node)
                continue

            if info['zone_label'] == 'external':
                node['zone'] = 'external'
                # User req: Only show public IP (127.0.0.1) for External Zone, hide internal subnet IP
                node['ip'] = "127.0.0.1"
                zones['external'].append(node)
            elif is_dmz and is_db:
                node['zone'] = 'intranet'
                zones['intranet'].append(node)
            elif is_dmz:
                node['zone'] = 'dmz'
                zones['dmz'].append(node)
            elif is_db:
                node['zone'] = 'database'
                zones['database'].append(node)
            elif include_stopped:
                # Stopped containers won't show up in network inspect, infer from compose override if possible
                working_dir = info.get('working_dir')
                inferred_zone = None
                if working_dir:
                    if working_dir in zone_cache:
                        inferred_zone = zone_cache[working_dir]
                    else:
                        inferred_zone = _infer_zone_from_workdir(working_dir)
                        zone_cache[working_dir] = inferred_zone

                if inferred_zone in zones:
                    node['zone'] = inferred_zone
                    zones[inferred_zone].append(node)
            
            
    except Exception as e:
        logger.error(f"Error fetching zone info: {e}")
        
    return zones

def _infer_zone_from_workdir(working_dir: str) -> Optional[str]:
    """Infer zone from docker-compose.override.yml networks in the working directory."""
    if not working_dir or not os.path.isdir(working_dir):
        return None

    override_path = os.path.join(working_dir, "docker-compose.override.yml")
    if not os.path.exists(override_path):
        return None

    try:
        with open(override_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return None

    networks_used: Set[str] = set()
    services = data.get('services', {}) or {}
    for svc_def in services.values():
        nets = svc_def.get('networks')
        if isinstance(nets, list):
            networks_used.update(nets)
        elif isinstance(nets, dict):
            networks_used.update(nets.keys())
        elif isinstance(nets, str):
            networks_used.add(nets)

    if NET_DMZ_NAME in networks_used and NET_DB_NAME in networks_used:
        return "intranet"
    if NET_DMZ_NAME in networks_used:
        return "dmz"
    if NET_DB_NAME in networks_used:
        return "database"

    return None

def _extract_cve_from_path(path: str) -> Dict[str, str]:
    if not path: return {}
    parts = path.replace('\\', '/').strip('/').split('/')
    try:
        if 'vulhub' in parts:
            idx = parts.index('vulhub')
            if len(parts) > idx + 2:
                return {"app": parts[idx+1], "cve": parts[idx+2]}
        if parts[-1].upper().startswith("CVE-"):
             return {"app": parts[-2], "cve": parts[-1]}
    except:
        pass
    return {}

TOOLS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../../tools"))

def copy_file_to_container(container_id: str, src_path: str, dest_path: str):
    logger.info(f"Copying {src_path} to {container_id}:{dest_path}")
    try:
        subprocess.run(["docker", "cp", src_path, f"{container_id}:{dest_path}"], check=True)
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to copy file: {e}")
        raise

def exec_container_cmd(container_id: str, cmd: str, workdir: str = "/tmp") -> str:
    docker_cmd = ["docker", "exec", "-w", workdir, container_id, "sh", "-c", cmd]
    res = subprocess.run(docker_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
    if res.returncode != 0:
        logger.warning(f"Exec failed in {container_id}: {cmd}. Stderr: {res.stderr}")
    return res.stdout

def exec_container_cmd_full(container_id: str, cmd: str, workdir: str = "/tmp") -> Dict[str, Any]:
    docker_cmd = ["docker", "exec", "-w", workdir, container_id, "sh", "-c", cmd]
    res = subprocess.run(docker_cmd, capture_output=True, text=True, encoding='utf-8', errors='ignore')
    if res.returncode != 0:
        logger.warning(f"Exec failed in {container_id}: {cmd}. Stderr: {res.stderr}")
    return {
        "stdout": res.stdout,
        "stderr": res.stderr,
        "returncode": res.returncode
    }

def _find_exploit_script(app: str, cve: str) -> Optional[str]:
    if not cve: return None
    norm_cve = cve.lower().replace("-", "").replace("_", "")
    norm_app = app.lower().replace("-", "").replace("_", "") if app else ""
    
    for root, dirs, files in os.walk(ATTACK_CHAINS_ROOT):
        norm_root = root.lower().replace("-", "").replace("_", "")
        if norm_cve in norm_root or (norm_app and norm_app in norm_root):
            for f in files:
                if f.endswith(".py"):
                    norm_f = f.lower().replace("-", "").replace("_", "")
                    if norm_cve in norm_f or (norm_app and norm_app in norm_f):
                        return os.path.join(root, f)
    
    # Fallback to a broader search
    for root, dirs, files in os.walk(ATTACK_CHAINS_ROOT):
        for f in files:
             if f.endswith(".py"):
                  norm_f = f.lower().replace("-", "").replace("_", "")
                  if norm_cve in norm_f:
                       return os.path.join(root, f)

    return None

def _get_exploit_category(exploit_script_path: str) -> str:
    """
    Extracts the category (RCE, sqli, fileread) from the exploit script path.
    Assumes standard structure: .../attack-chains/<CATEGORY>/<CVE>/<SCRIPT.py>
    """
    try:
        # Normalize path separators
        path = os.path.normpath(exploit_script_path)
        # Split path
        parts = path.split(os.sep)
        
        # Find 'attack-chains' in path
        if 'attack-chains' in parts:
            idx = parts.index('attack-chains')
            if idx + 1 < len(parts):
                category = parts[idx + 1]
                return category
    except Exception as e:
        logger.error(f"Error extracting category from {exploit_script_path}: {e}")
    
    return "unknown"

def run_local_exploit(container_id: str) -> Dict[str, Any]:
    """
    Run an exploit script from the manager against a container in the External zone (or accessible directly).
    Iterates through all discovered ports until success.
    """
    # 1. Get Container Info
    zones = fetch_zone_data()
    # Flatten - include internal nodes just in case direct access is possible (e.g. flat network)
    all_nodes = zones['external'] + zones['dmz'] + zones['intranet'] + zones['database']
    target_node = next((n for n in all_nodes if n['id'] == container_id), None)
    
    if not target_node:
        return {"status": "error", "message": "Container not found"}

    # 2. Determine Connection Info (Candidate URLs)
    candidate_urls = []
    aifw_enabled = aifw_service.is_aifw_enabled()
    
    # User Request: Bypass AIFW for External Zone (Entry Machine) to ensure initial access success
    # If the target is in the External zone, we skip AIFW interception and treat it as a direct connection
    use_aifw = aifw_enabled and target_node.get('zone') != 'external'
    
    if use_aifw:
        # AIFW mode: prioritize internal IPs so traffic goes through Docker bridge → AIFW gateway
        logger.info(f"[AIFW] AIFW enabled, using internal IPs for {container_id}")
        if target_node['ip'] and target_node['ip'] != "127.0.0.1":
            target_ip = target_node['ip'].split(',')[0].strip()
            # Add intercept rules for all internal ports
            if target_node['ports']:
                for p in target_node['ports']:
                    port = None
                    if "->" in p:
                        try:
                            inner = p.split("->")[1].strip()
                            port = inner.split("/")[0] if "/" in inner else inner
                        except: pass
                    elif "/" in p:
                        try: port = p.split("/")[0]
                        except: pass
                    if port:
                        res = aifw_service.add_intercept_rule(target_ip, port)
                        # Use Host Loopback + AIFW Local Port (exposed in docker-compose)
                        # This ensures Windows/Mac users can reach the target via AIFW.
                        if res and res.get("local_port"):
                            # On Host, we access AIFW via localhost mapped ports
                            candidate_urls.append(f"http://127.0.0.1:{res['local_port']}")
                            # Also add internal IP just in case we are inside the network
                            candidate_urls.append(f"http://{target_ip}:{port}")
                        else:
                            candidate_urls.append(f"http://{target_ip}:{port}")
            if not candidate_urls:
                candidate_urls.append(f"http://{target_ip}")
    else:
        # Normal mode: prefer mapped ports
        # Strategy 1: External Mapped Ports (Preferred for local exploit if available)
        if target_node['ports']:
            for p in target_node['ports']:
                if "->" in p:
                    external_part = p.split("->")[0].strip()
                    # If "0.0.0.0:8080" or ":::8080", we use localhost/127.0.0.1
                    if ":" in external_part:
                        port = external_part.split(":")[-1]
                        candidate_urls.append(f"http://127.0.0.1:{port}")

    if not use_aifw:
        # Strategy 2: Internal IP Ports (always as backup)
        # This block will add internal IPs if AIFW is not enabled, or if AIFW is enabled but no ports were found
        # and the initial target_ip was added without a port. It also handles cases where target_node['ip'] is 127.0.0.1
        # and thus not handled by the AIFW block.
        if target_node['ip'] and target_node['ip'] != "127.0.0.1":
            # Simply using IP might work for default port 80?
            candidate_urls.append(f"http://{target_node['ip']}")
            
            # Attempt to append port if available
            if target_node['ports']:
                for p in target_node['ports']:
                    port = None
                    if "->" in p:
                         try:
                            inner = p.split("->")[1].strip()
                            port = inner.split("/")[0] if "/" in inner else inner
                         except: pass
                    elif "/" in p:
                         try: port = p.split("/")[0]
                         except: pass
                    
                    if port:
                        candidate_urls.append(f"http://{target_node['ip']}:{port}")

    # Deduplicate
    candidate_urls = list(dict.fromkeys(candidate_urls))

    if not candidate_urls:
         # Try at least the IP if we have it
         if target_node['ip']:
             candidate_urls.append(f"http://{target_node['ip']}")
         else:
             return {"status": "error", "message": f"Could not determine target URL. Info: {target_node}"}

    # 3. Find Script
    cve_info = target_node.get('cve_info', {})
    target_cve = cve_info.get('cve')
    target_app = cve_info.get('app')
    
    if not target_cve:
        return {"status": "error", "message": "No CVE info found for container."}

    exploit_script = _find_exploit_script(target_app, target_cve)
    if not exploit_script:
        return {"status": "error", "message": f"No exploit script found for {target_cve} (App: {target_app})"}

    # Determine Pwn Type by Category
    category = _get_exploit_category(exploit_script)
    pwn_type = "RCE" # Default
    if category.lower() == "fileread":
        pwn_type = "FILEREAD"
    elif category.lower() == "sqli":
        pwn_type = "SQLI"
    elif category.upper() == "RCE":
        pwn_type = "RCE"

    # 4. Run Script Loop
    is_rce = pwn_type == "RCE" or pwn_type == "SQLI" # SQLI also might use file write checks like RCE
    # Note: For SQLI that writes file (like 1panel), we treat verification similar to RCE (checking marker file)
    # But for display, we want to distinguish.
    
    is_fileread = pwn_type == "FILEREAD"
    
    if is_rce: # SQLI writing file also falls here for command arg purposes
        target_command = "touch /tmp/success"
    elif is_fileread:
        target_command = "/etc/passwd" 
    else:
        target_command = "whoami"
    
    cwd = os.path.dirname(exploit_script) if os.path.dirname(exploit_script) else None
    final_output = ""

    for target_url in candidate_urls:
        if not target_url.startswith("http"):
            target_url = f"http://{target_url}"
            
        final_output += f"\n--- Attempting Target: {target_url} ---\n"
        
        cmd_args = [sys.executable, exploit_script, target_url, target_command]
        logger.info(f"Running local exploit: {cmd_args}")
        
        try:
            res = subprocess.run(
                cmd_args,
                cwd=cwd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                timeout=20 
            )
            final_output += f"Command: {' '.join(cmd_args)}\nExit Code: {res.returncode}\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}\n"
            
            # 5. Verify Success
            pwned = False
            check_cmd = "ls /tmp/success"

            if is_rce: # Valid for RCE and SQLI (that writes file)
                verify = exec_container_cmd(container_id, check_cmd)
                if "/tmp/success" in verify:
                    pwned = True
            elif is_fileread:
                # Check for echo/stdout content
                if len(res.stdout.strip()) > 0:
                    pwned = True
            elif res.returncode == 0:
                 pwned = True

            if pwned:
                mark_as_compromised(container_id, pwn_type)
                if is_rce: exec_container_cmd(container_id, "rm /tmp/success")
                
                if pwn_type == "RCE":
                    status_msg = "Target PWNED."
                elif pwn_type == "FILEREAD":
                    status_msg = "File Read Success (可以通过框选择文件读取)."
                elif pwn_type == "SQLI":
                    status_msg = "SQLI Success"
                else:
                    status_msg = "Exploit Success"

                msg = f"Exploit executed successfully on {target_url}. {status_msg}"
                return {"status": "success", "message": msg, "output": final_output}

            # Fallback for RCE or FileRead if Python failed
            if (is_rce or is_fileread) and not pwned:
                final_output += "\n--- Python Exploit Failed, Attempting Binary Fallback ---\n"
                binary_path = os.path.splitext(exploit_script)[0]
                if os.path.exists(binary_path):
                    try:
                        st = os.stat(binary_path)
                        os.chmod(binary_path, st.st_mode | 0o111)
                    except Exception as e:
                        final_output += f"\nFailed to chmod binary: {e}"

                    bin_cmd_args = [binary_path, target_url, target_command]
                    logger.info(f"Running fallback binary: {bin_cmd_args}")
                    
                    try:
                        res_bin = subprocess.run(
                            bin_cmd_args,
                            cwd=cwd,
                            capture_output=True,
                            text=True,
                            encoding='utf-8',
                            timeout=60
                        )
                        final_output += f"\nBinary Command: {' '.join(bin_cmd_args)}\nExit Code: {res_bin.returncode}\nSTDOUT:\n{res_bin.stdout}\nSTDERR:\n{res_bin.stderr}"
                        
                        # Verify again
                        pwned_bin = False
                        if is_rce:
                            verify = exec_container_cmd(container_id, check_cmd)
                            if "/tmp/success" in verify:
                                pwned_bin = True
                        elif is_fileread:
                            if len(res_bin.stdout.strip()) > 0:
                                pwned_bin = True
                        
                        if pwned_bin:
                            mark_as_compromised(container_id, pwn_type)
                            if is_rce: exec_container_cmd(container_id, "rm /tmp/success")
                            return {"status": "success", "message": "Fallback Binary Exploit executed successfully on {target_url}.", "output": final_output}
                    except Exception as e:
                        final_output += f"\nBinary execution error: {e}"
                else:
                    final_output += f"\nFallback executable not found at {binary_path}"

        except subprocess.TimeoutExpired:
            final_output += "\nExploit execution timed out."
        except Exception as e:
            final_output += f"\nExecution error: {str(e)}"
            
    # Double check with delay if still not pwned (after trying all ports)
    if is_rce:
        final_output += "\n\n[-] All immediate attempts failed. Waiting 15s for delayed execution check...\n"
        time.sleep(15)
        verify_final = exec_container_cmd(container_id, check_cmd)
        if "/tmp/success" in verify_final:
             mark_as_compromised(container_id, pwn_type)
             exec_container_cmd(container_id, "rm /tmp/success")
             return {"status": "success", "message": "Delayed execution succeeded. Target PWNED.", "output": final_output}
        else:
             final_output += "[-] Delayed check failed. /tmp/success not found.\n"
            
    # End of loop
    return {"status": "failed", "message": "All attempts failed.", "output": final_output}

import sys

def run_custom_exploit_cmd(container_id: str, command_args: str) -> Dict[str, Any]:
    # 1. Get Container Info
    zones = fetch_zone_data()
    all_nodes = zones['external'] + zones['dmz'] + zones['intranet'] + zones['database']
    target_node = next((n for n in all_nodes if n['id'] == container_id), None)
    
    if not target_node:
        return {"status": "error", "message": "Container not found"}

    # 3. Find Script (reuse logic)
    cve_info = target_node.get('cve_info', {})
    target_cve = cve_info.get('cve')
    target_app = cve_info.get('app')
    if not target_cve: return {"status": "error", "message": "No CVE info found"}
    exploit_script = _find_exploit_script(target_app, target_cve)
    if not exploit_script: return {"status": "error", "message": "Exploit script not found"}

    # 2. Determine Connection Info (Try best guess IP)
    target_url = None
    if target_node['ports']:
        for p in target_node['ports']:
            if "->" in p:
                external_part = p.split("->")[0].strip()
                if ":" in external_part:
                    port = external_part.split(":")[-1]
                    target_url = f"http://127.0.0.1:{port}"
                    break
    if not target_url and target_node['ip']:
        target_url = f"http://{target_node['ip']}"
        
    if not target_url: return {"status": "error", "message": "Could not determine URL"}

    cwd = os.path.dirname(exploit_script) if os.path.dirname(exploit_script) else None
    
    # Run
    cmd_args = [sys.executable, exploit_script, target_url, command_args]
    try:
        res = subprocess.run(
            cmd_args,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding='utf-8',
            timeout=10
        )
        return {"status": "success", "output": res.stdout + res.stderr}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def mark_as_compromised(container_id: str, pwn_type: str = "RCE"):
    COMPROMISED_CONTAINERS[container_id] = pwn_type

def get_compromise_type(container_id: str) -> Optional[str]:
    return COMPROMISED_CONTAINERS.get(container_id)

def run_pivoting_attack(start_container_id: str, target_container_id: Optional[str] = None) -> List[str]:
    results = []
    mark_as_compromised(start_container_id)
    
    if target_container_id:
        results.append(f"Starting targeted pivot from {start_container_id} against {target_container_id}...")
        
        # Targeted Attack Mode
        zones = fetch_zone_data()
        all_nodes = zones['dmz'] + zones['database'] + zones['intranet'] + zones['external']
        target_node = next((n for n in all_nodes if n['id'] == target_container_id), None)
        
        if not target_node:
            results.append("[-] Target container not found.")
            return results
            
        # Get target IPs (internal)
        target_ip_raw = target_node['ip']
        target_ips = [ip.strip() for ip in target_ip_raw.split(',')] if ',' in target_ip_raw else [target_ip_raw]
        target_ip = target_ips[0] # Used for display naming

        # AIFW: setup routing for the source container
        if aifw_service.is_aifw_enabled():
            source_node = next((n for n in all_nodes if n['id'] == start_container_id), None)
            source_zone = source_node['zone'] if source_node else 'dmz'
            aifw_service.setup_container_routing(start_container_id, source_zone)
            logger.info(f"[AIFW] Pivoting attack: routing set for {start_container_id} with zone {source_zone}")
             
        # Extract internal ports
        target_ports = []
        if target_node['ports']:
            for p in target_node['ports']:
                # Format: "host_port->container_port/proto"
                if "->" in p:
                    # "0.0.0.0:2222->2222/tcp" -> "2222"
                    try:
                        internal_part = p.split("->")[1].strip()
                        if "/" in internal_part:
                            target_ports.append(internal_part.split("/")[0])
                        else:
                            target_ports.append(internal_part)
                    except: pass
                elif "/" in p:
                     try:
                         target_ports.append(p.split("/")[0])
                     except: pass
        
        # Deduplicate
        target_ports = list(dict.fromkeys(target_ports))

        results.append(f"Target identified: {target_node['name']} ({target_ip}:{','.join(target_ports) if target_ports else 'default'})")

        # AIFW: add intercept rules for the pivot target
        if aifw_service.is_aifw_enabled() and target_ports:
            for tip in target_ips:
                for tport in target_ports:
                    aifw_service.add_intercept_rule(tip, tport)
                    results.append(f"[AIFW] Intercept rule added for {tip}:{tport}")
        
        # Kept for compatibility with later code
        target_port = target_ports[0] if target_ports else None
        
        cve_info = target_node.get('cve_info', {})
        target_cve = cve_info.get('cve')
        target_app = cve_info.get('app')
        
        if not target_cve:
             results.append(f"[-] No CVE info identified for {target_container_id}.")
             return results

        exploit_script = _find_exploit_script(target_app, target_cve)
        if not exploit_script:
            results.append(f"[-] No exploit script found for {target_cve}.")
            return results
            
        results.append(f"Attacking {target_ip} ({target_cve})...")
        script_name = os.path.basename(exploit_script)
        remote_script = f"/tmp/{script_name}"
        
        # Determine if binary fallback is available
        binary_path = os.path.splitext(exploit_script)[0] # remove .py
        binary_name = os.path.basename(binary_path)
        remote_binary = f"/tmp/{binary_name}"
        has_binary = False
        
        try:
            exploit_dir = os.path.dirname(exploit_script)
            if exploit_dir and os.path.isdir(exploit_dir):
                for f in os.listdir(exploit_dir):
                    f_path = os.path.join(exploit_dir, f)
                    if os.path.isfile(f_path):
                        copy_file_to_container(start_container_id, f_path, f"/tmp/{f}")
            else:
                copy_file_to_container(start_container_id, exploit_script, remote_script)
                
            if os.path.exists(binary_path):
                 copy_file_to_container(start_container_id, binary_path, remote_binary)
                 exec_container_cmd(start_container_id, f"chmod +x {remote_binary}")
                 has_binary = True
        except Exception as e:
            results.append(f"[-] Failed to upload tools: {e}")
            return results
            
        script_content_lower = ""
        try:
            with open(exploit_script, 'r', encoding='utf-8', errors='ignore') as f:
                script_content_lower = f.read().lower()
        except: pass

        category = _get_exploit_category(exploit_script)
        pwn_type = "RCE" # Default
        if category.lower() == "fileread":
            pwn_type = "FILEREAD"
        elif category.lower() == "sqli":
            pwn_type = "SQLI"
        elif category.upper() == "RCE":
            pwn_type = "RCE"

        is_fileread = pwn_type == "FILEREAD"
        is_rce = pwn_type == "RCE" or pwn_type == "SQLI" # Same as local logic
        
        target_netloc = f"{target_ip}"
        if target_port:
             target_netloc = f"{target_ip}:{target_port}"

        marker_file = "/tmp/success"
        pwned = False

        if is_fileread:
             # FILEREAD Logic
             results.append(f"[*] Detected File Read vulnerability type.")
             candidate_netlocs = []
             candidate_netlocs.extend(target_ips)
             
             if target_node.get('ports'):
                 for p in target_node['ports']:
                     port = None
                     if "->" in p:
                          try:
                             port_str = p.split("->")[1].strip()
                             port = port_str.split("/")[0] if "/" in port_str else port_str
                          except: pass
                     elif "/" in p:
                          port = p.split("/")[0]
                     if port: 
                         for tip in target_ips:
                             candidate_netlocs.append(f"{tip}:{port}")
             candidate_netlocs = list(dict.fromkeys(candidate_netlocs))

             target_file = "/etc/passwd"
             success_indicator = "root:"
             pwned = False

             for netloc in candidate_netlocs:
                 if pwned: break
                 target_url = f"http://{netloc}"
                 
                 # Try typical usage: python exploit.py url file
                 cmd = f"python3 {remote_script} {target_url} {target_file}"
                 results.append(f"Executing: {cmd}")
                 out = exec_container_cmd(start_container_id, cmd)
                 results.append(f"Output: {out[:300]}...") # Log partial output

                 if success_indicator in out:
                     pwned = True
                     results.append(f"SUCCESS: Successfully read {target_file} on {netloc}")
                 elif has_binary:
                     # Binary Fallback
                     results.append(f"[-] Python exploit failed. Trying fallback binary on {netloc}")
                     cmd_bin = f"{remote_binary} {target_url} {target_file}"
                     results.append(f"Executing Binary: {cmd_bin}")
                     out_bin = exec_container_cmd(start_container_id, cmd_bin)
                     results.append(f"Output: {out_bin[:300]}...")
                     
                     if success_indicator in out_bin:
                        pwned = True
                        results.append(f"SUCCESS: Binary exploit succeeded.")
            
             if pwned:
                mark_as_compromised(target_node['id'], pwn_type='FILEREAD')
             else:
                results.append(f"FAILED: Could not verify File Read on {target_ip}")

        elif is_rce:
            # Method 1: Python
            # Try all candidates ports
            candidate_netlocs = []
            candidate_netlocs.extend(target_ips)
            
            if target_node.get('ports'):
                for p in target_node['ports']:
                    port = None
                    if "->" in p:
                         try:
                            port_str = p.split("->")[1].strip()
                            port = port_str.split("/")[0] if "/" in port_str else port_str
                         except: pass
                    elif "/" in p:
                         port = p.split("/")[0]
                    if port: 
                         for tip in target_ips:
                             candidate_netlocs.append(f"{tip}:{port}")
            candidate_netlocs = list(dict.fromkeys(candidate_netlocs))

            pwned = False
            
            for netloc in candidate_netlocs:
                if pwned: break
                
                target_url = f"http://{netloc}"
                cmd = f"python3 {remote_script} {target_url} 'touch {marker_file}'"
                results.append(f"Executing: {cmd}")
                exec_container_cmd(start_container_id, cmd)
                
                check = exec_container_cmd(target_node['id'], f"ls {marker_file}")
                if marker_file in check:
                    pwned = True
                elif has_binary:
                    # Method 2: Binary Fallback
                    results.append(f"[-] Python exploit failed. Trying fallback binary on {netloc}")
                    cmd_bin = f"{remote_binary} {target_url} 'touch {marker_file}'"
                    results.append(f"Executing Binary: {cmd_bin}")
                    exec_container_cmd(start_container_id, cmd_bin)
                    
                    check_bin = exec_container_cmd(target_node['id'], f"ls {marker_file}")
                    if marker_file in check_bin:
                        pwned = True
                        results.append(f"SUCCESS: Binary exploit succeeded.")

            # Double check with delay if still not pwned
            if not pwned:
                results.append("[-] Immediate check failed. Waiting 15s for delayed execution...")
                time.sleep(15)
                check_final = exec_container_cmd(target_node['id'], f"ls {marker_file}")
                if marker_file in check_final:
                    pwned = True
                    results.append("SUCCESS: Delayed execution succeeded!")

            if pwned:
                # Use detected category logic
                comp_type = "RCE"
                if pwn_type == "FILEREAD": comp_type = "FILEREAD"
                elif pwn_type == "SQLI": comp_type = "SQLI"

                mark_as_compromised(target_node['id'], comp_type)
                # Cleanup
                # exec_container_cmd(target_node['id'], f"rm {marker_file}") # 删除标识文件
                results.append(f"SUCCESS: Pwned {target_ip}!")
            else:
                 results.append(f"FAILED: Could not verify RCE on {target_ip}")
        else:
             pwned_any = False
             for tip in target_ips:
                 target_url = f"http://{tip}"
                 # Simple non-RCE tries mostly HTTP
                 cmd = f"python3 {remote_script} {target_url} whoami"
                 results.append(f"Executing: {cmd}")
                 out = exec_container_cmd(start_container_id, cmd)
                 # ... Non-RCE checks usually rely on stdout, complicated to verify in pivoting without agent
                 results.append(f"Output: {out[:200]}...")
                 if "error" not in out.lower() and len(out) > 0:
                      mark_as_compromised(target_node['id'])
                      results.append(f"SUCCESS: {tip} seems vulnerable (Non-RCE)")
                      pwned_any = True
                      break
             if pwned_any:
                 return results
        return results

    # Standard Auto-Pivot Mode (original logic)
    results.append(f"Starting auto-pivot scan from {start_container_id}...")

    # Upload Tools
    busybox_path = os.path.join(TOOLS_DIR, "busybox")
    fscan_path = os.path.join(TOOLS_DIR, "fscan")
    
    try:
        copy_file_to_container(start_container_id, busybox_path, "/tmp/busybox")
        copy_file_to_container(start_container_id, fscan_path, "/tmp/fscan")
        exec_container_cmd(start_container_id, "chmod +x /tmp/busybox /tmp/fscan")
    except Exception as e:
        results.append(f"Error setting up tools: {e}")
        return results

    # Get Subnet
    ifconfig_out = exec_container_cmd(start_container_id, "ifconfig || /tmp/busybox ifconfig")
    ip_match = re.search(r'inet (?:addr:)?(\d+\.\d+\.\d+\.\d+)', ifconfig_out)
    if not ip_match:
        results.append("Could not determine IP address.")
        return results
    
    my_ip = ip_match.group(1)
    subnet = my_ip.rsplit('.', 1)[0] + ".0/24"
    results.append(f"Scanning subnet {subnet} from {my_ip}...")

    # Scan
    results.append("Executing fscan (redirecting to /tmp/result.txt)...")
    # Run fscan and redirect to file. exec_container_cmd uses subprocess.run which waits for the command to finish.
    # This acts as a dynamic "wait until done" rather than a fixed sleep.
    cmd_scan = f"/tmp/fscan -h {subnet} -nopoc -nobr > /tmp/result.txt"
    exec_container_cmd(start_container_id, cmd_scan)
    
    # Read result
    scan_out = exec_container_cmd(start_container_id, "cat /tmp/result.txt")
    results.append(f"--- Raw Scan Result ---\n{scan_out}\n-----------------------")
    
    # Parse Targets
    found_ips = set(re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', scan_out))
    if my_ip in found_ips: found_ips.remove(my_ip)
    
    # Filter gateway broadly (usually .1, but let's just log what we found)
    gateway = my_ip.rsplit('.', 1)[0] + ".1"
    if gateway in found_ips: found_ips.remove(gateway)

    if not found_ips:
        results.append("Scan finished. No other hosts found.")
        results.append(f"Raw scan output (first 200 chars): {scan_out[:200]}")
        return results

    results.append(f"Found targets: {', '.join(found_ips)}")

    # Attack Targets
    zones = fetch_zone_data()
    all_nodes = zones['dmz'] + zones['database'] + zones['intranet']

    for ip in found_ips:
        results.append(f"Analyzing {ip}...")
        target_node = next((n for n in all_nodes if n['ip'] == ip or ip in n.get('ips', [])), None)
        if not target_node:
            results.append(f"[-] {ip} not managed by this system (unknown container).")
            continue
            
        if target_node['is_compromised']:
            results.append(f"[*] {ip} is already compromised. Skipping.")
            continue
            
        cve_info = target_node.get('cve_info', {})
        target_cve = cve_info.get('cve')
        target_app = cve_info.get('app')
        
        if not target_cve:
             results.append(f"[-] No CVE info identified for {ip} (App: {target_app}).")
             continue

        exploit_script = _find_exploit_script(target_app, target_cve)
        
        if exploit_script:
            # Extract internal ports (Candidates)
            candidate_netlocs = []
            
            # Always try pure IP (some internal services are on default ports)
            candidate_netlocs.append(ip)

            if target_node.get('ports'):
                for p in target_node['ports']:
                    port = None
                    if "->" in p:
                        try:
                            internal_part = p.split("->")[1].strip()
                            port = internal_part.split("/")[0] if "/" in internal_part else internal_part
                        except: pass
                    elif "/" in p:
                        try:
                            port = p.split("/")[0]
                        except: pass
                    
                    if port:
                        candidate_netlocs.append(f"{ip}:{port}")
            
            candidate_netlocs = list(dict.fromkeys(candidate_netlocs))

            results.append(f"Attacking {ip} ({target_cve}). Candidates: {candidate_netlocs}...")
            
            script_name = os.path.basename(exploit_script)
            remote_script = f"/tmp/{script_name}"
            
            exploit_dir = os.path.dirname(exploit_script)
            if exploit_dir and os.path.isdir(exploit_dir):
                for f in os.listdir(exploit_dir):
                    f_path = os.path.join(exploit_dir, f)
                    if os.path.isfile(f_path):
                        copy_file_to_container(start_container_id, f_path, f"/tmp/{f}")
            else:
                copy_file_to_container(start_container_id, exploit_script, remote_script)
            
            is_rce = "RCE" in exploit_script or "RCE" in os.path.dirname(exploit_script) or "CVE-2024-39907" in script_name
            pwned_this_target = False

            for netloc in candidate_netlocs:
                if pwned_this_target: break
                
                target_url = f"http://{netloc}"
                
                if is_rce:
                    marker_file = "/tmp/success"
                    cmd = f"python3 {remote_script} {target_url} 'touch {marker_file}'"
                    exec_container_cmd(start_container_id, cmd)
                    
                    check = exec_container_cmd(target_node['id'], f"ls {marker_file}")
                    if marker_file in check:
                        # Determine pwn type: specific override for known SQLI that act like RCE (file write), or general check
                        actual_type = "RCE"
                        if "CVE-2024-39907" in script_name or "sqli" in exploit_script.lower():
                            actual_type = "SQLI"
                            
                        mark_as_compromised(target_node['id'], actual_type)
                        results.append(f"SUCCESS: Pwned {ip} on {netloc}!")
                        
                        # Recursive pivot
                        sub_results = run_pivoting_attack(target_node['id'])
                        results.extend(sub_results)
                        
                        pwned_this_target = True
                else:
                     cmd = f"python3 {remote_script} {target_url} whoami"
                     out = exec_container_cmd(start_container_id, cmd)
                     # Loose check for success for non-RCE
                     if "error" not in out.lower() and len(out) > 0:
                          mark_as_compromised(target_node['id'], "SQLI")
                          results.append(f"SUCCESS: {ip} seems vulnerable on {netloc} (SQLI Success)")
                          pwned_this_target = True
            
            if not pwned_this_target:
                 results.append(f"FAILED: Could not verify exploit on {ip}")
        else:
            results.append(f"No exploit for {target_cve} on {ip}")

    return results
