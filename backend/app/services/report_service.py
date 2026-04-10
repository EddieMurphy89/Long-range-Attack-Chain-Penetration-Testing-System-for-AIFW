"""
Attack Chain Report Generation Agent Service.
Collects attack chain data (compromised nodes + edges) and uses LLM to generate
a comprehensive penetration test report with chain visualization and defense recommendations.
"""
import json
from typing import List, Dict, Any, AsyncGenerator
from openai import AsyncOpenAI
from app.core.config import logger, OPENAI_API_KEY, OPENAI_BASE_URL, OPENAI_MODEL_NAME
from app.services import docker_service


def collect_attack_chain_data(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Merge frontend-provided attack chain data with live backend zone data
    to build a comprehensive attack chain summary for the LLM.
    """
    # Get live zone data from docker for enrichment
    try:
        live_zones = docker_service.fetch_zone_data(include_stopped=False)
        live_nodes_map = {}
        for zone_name, zone_nodes in live_zones.items():
            if zone_name == "aifw":
                continue
            for n in zone_nodes:
                live_nodes_map[n["id"]] = n
    except Exception as e:
        logger.warning(f"Failed to fetch live zone data for report: {e}")
        live_nodes_map = {}

    # Build compromised nodes list with enriched data
    compromised_nodes = []
    all_nodes_map = {}

    for node in nodes:
        node_id = node.get("id", "")
        all_nodes_map[node_id] = node

        # Only include compromised nodes in the report
        if not node.get("pwn_type"):
            continue

        # Enrich with live data if available
        live = live_nodes_map.get(node_id, {})

        compromised_nodes.append({
            "id": node_id[:12],
            "name": node.get("name", live.get("name", "unknown")),
            "ip": node.get("ip", live.get("ip", "unknown")),
            "zone": node.get("zone", live.get("zone", "unknown")),
            "pwn_type": node.get("pwn_type", live.get("pwn_type", "unknown")),
            "cve": node.get("cve", ""),
            "app": node.get("app", ""),
        })

    # Build attack path edges (only success edges)
    attack_edges = []
    for edge in edges:
        if edge.get("status") != "success":
            continue
        src_id = edge.get("sourceId", "")
        tgt_id = edge.get("targetId", "")
        src_node = all_nodes_map.get(src_id, {})
        tgt_node = all_nodes_map.get(tgt_id, {})
        attack_edges.append({
            "from": f"{src_node.get('name', src_id[:12])} ({src_node.get('zone', '?')}:{src_node.get('ip', '?')})",
            "to": f"{tgt_node.get('name', tgt_id[:12])} ({tgt_node.get('zone', '?')}:{tgt_node.get('ip', '?')})",
            "target_cve": tgt_node.get("cve", ""),
            "target_pwn_type": tgt_node.get("pwn_type", ""),
        })

    return {
        "compromised_count": len(compromised_nodes),
        "total_nodes": len(nodes),
        "compromised_nodes": compromised_nodes,
        "attack_edges": attack_edges,
    }


async def generate_attack_report(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    api_key: str = "",
    base_url: str = "",
    model_name: str = "",
) -> AsyncGenerator[str, None]:
    """
    Generate a comprehensive attack chain report using LLM.
    Yields markdown chunks via SSE streaming.
    """
    key_to_use = api_key or OPENAI_API_KEY
    if not key_to_use:
        yield json.dumps({"type": "error", "content": "API Key is not configured. Please set it in the Agent settings page."})
        yield json.dumps({"type": "done"})
        return

    client = AsyncOpenAI(
        api_key=key_to_use,
        base_url=base_url or OPENAI_BASE_URL,
    )
    effective_model = model_name or OPENAI_MODEL_NAME

    # Collect and structure data
    chain_data = collect_attack_chain_data(nodes, edges)

    if chain_data["compromised_count"] == 0:
        yield json.dumps({"type": "error", "content": "No compromised nodes found. Please complete at least one attack before generating a report."})
        yield json.dumps({"type": "done"})
        return

    yield json.dumps({"type": "status", "content": "Collecting attack chain data..."})

    chain_json = json.dumps(chain_data, ensure_ascii=False, indent=2)

    yield json.dumps({"type": "status", "content": f"Analyzing {chain_data['compromised_count']} compromised nodes..."})

    prompt = f"""你是一位资深的网络安全渗透测试专家，请根据以下攻击链数据，生成一份专业、完整的渗透测试攻击报告。

【攻击链数据(JSON)】：
```json
{chain_json}
```

【报告要求】：
请严格按照以下结构输出 Markdown 格式的报告，每个章节都必须包含：

## 1. 攻击链总览

用一段话概括本次渗透测试的整体链路，从入口点到最深层目标的完整渗透路径概述。

## 2. 被攻破机器清单

用 Markdown 表格列出所有被攻破的机器，包含以下列：
| 序号 | 容器名称 | 网络区域 | IP地址 | CVE编号 | 关联服务/应用 | 攻破类型 |

其中攻破类型包括 RCE(远程代码执行)、FILEREAD(任意文件读取)、SQLI(SQL注入) 等。

## 3. 攻击链路展示

使用 Mermaid 流程图来展示攻击链路关系（用 ```mermaid 代码块），展示从攻击者到各目标节点的渗透路径。节点应包含区域和IP信息。

## 4. 各节点漏洞详情

对每个被利用的 CVE 漏洞进行简要分析，包括：
- 漏洞编号与名称
- 影响的服务/组件
- 漏洞原理简述
- 攻击利用方式

## 5. MITRE ATT&CK® 战术与技术映射（结构化展示）

本章节须体现与 **MITRE ATT&CK for Enterprise** 的对照，便于论文/答辩中的「威胁建模与攻击阶段归类」表述。须同时包含 **表格展示** 与 **简要文字分析**，不得仅用一段话笼统概括。

### 5.1 ATT&CK 映射总表（必填）

使用 Markdown 表格，按攻击时间顺序或拓扑推进顺序逐行映射，至少包含以下列（列名须保留）：

| 步骤 | 攻击链中的动作/节点（简述） | ATT&CK 战术（中文名） | 战术 ID (TAxxxx) | 技术（中文名） | 技术 ID (Txxxx 或 Txxxx.xxx) | 映射依据（与 CVE/攻破类型/跳转关系的对应） |

要求：
- 战术 ID 须使用 Enterprise 矩阵中的 **TA** 编号（如 TA0001 Initial Access、TA0008 Lateral Movement 等）；技术须给出 **T** 编号，若有合适子技术须写出 **Txxxx.xxx**。
- 常见对应可参考（须结合本题实际数据选用，勿机械照搬）：入口利用 Web 漏洞 → T1190 Exploit Public-Facing Application；RCE/命令执行 → T1059 Command and Scripting Interpreter；凭据/敏感文件 → T1552 Unsecured Credentials、T1083 File and Directory Discovery；内网跳转/扫描 → T1046 Network Service Discovery、T1021 Remote Services 等。
- 若某一步可对应多条技术，可分多行或在该行「映射依据」中并列说明优先级。

### 5.2 ATT&CK 战术阶段覆盖图（必填）

除表格外，须再给出 **一张 Mermaid 图**（单独 ```mermaid 代码块），用于展示本次链路覆盖到的 **战术阶段** 在 kill chain 上的先后或并行关系。推荐用法之一：
- 使用 `flowchart LR` 或 `flowchart TD`，节点为「TA 编号 + 战术简称」，边表示攻击推进顺序；或
- 使用 `timeline` / `gantt`（若渲染环境支持）标出各战术阶段。

图下用 2～4 句中文说明：覆盖了 ATT&CK 矩阵中哪些战术域、是否存在明显缺口（例如未体现持久化、命令与控制等）。

### 5.3 学术化小结（必填）

用一小段话归纳：本次实验/渗透路径在 ATT&CK 视角下的 **主要威胁类型** 与 **检测防护应侧重的战术层**，并注明映射基于 MITRE ATT&CK® Enterprise 框架（可在脚注或句中说明版本以 ATT&CK 官网当前 Enterprise 为准）。

## 6. 针对性防御建议

针对本次攻击链中被利用的每个漏洞，给出具体的修复方案和安全加固建议。应包括：
- 补丁升级建议
- 配置加固措施
- 网络层面隔离建议
- 监控与检测建议

## 7. 总结

对本次渗透测试做全面总结，评估整体安全风险等级，并给出优先修复顺序建议。

【约束】：
- 输出必须是 Markdown 格式
- Mermaid 图必须使用 ```mermaid 代码块；**至少两张**：一张为第 3 节攻击拓扑，一张为第 5.2 节 ATT&CK 战术阶段图
- 表格必须使用标准 Markdown 表格语法（含第 5.1 节 ATT&CK 映射总表）
- 语言使用中文（MITRE 官方英文战术/技术名可在括号内保留）
- 如果 CVE 编号为空，则根据容器名称和应用推断可能的漏洞信息
- 报告应专业、详尽、可直接用于安全审计与学术文档附录
"""

    try:
        yield json.dumps({"type": "status", "content": "Report Agent generating report..."})

        response = await client.chat.completions.create(
            model=effective_model,
            messages=[
                {
                    "role": "system",
                    "content": "You are a senior cybersecurity penetration testing expert. Generate professional, detailed attack chain reports in Chinese Markdown. Always include: (1) a Mermaid diagram for the attack topology, (2) a MITRE ATT&CK for Enterprise mapping table with TA/T IDs, (3) a second Mermaid diagram showing covered ATT&CK tactic phases in order.",
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.3,
            stream=True,
        )

        full_report_content = ""
        async for chunk in response:
            content = chunk.choices[0].delta.content
            if content:
                full_report_content += content
                yield json.dumps({"type": "chunk", "content": content})

        # --- Save history ---
        try:
            import os
            from datetime import datetime
            
            history_dir = "targetzone_history"
            if not os.path.exists(history_dir):
                os.makedirs(history_dir)
                
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"report_{chain_data['compromised_count']}nodes_{timestamp}.md"
            filepath = os.path.join(history_dir, filename)
            
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(full_report_content)
                
            yield json.dumps({"type": "status", "content": f"Report saved to {filepath}"})
        except Exception as e:
            logger.error(f"Failed to save report to history: {e}")

        yield json.dumps({"type": "done"})

    except Exception as e:
        logger.error(f"Report generation LLM error: {e}")
        yield json.dumps({"type": "error", "content": f"Report generation failed: {str(e)}"})
        yield json.dumps({"type": "done"})
