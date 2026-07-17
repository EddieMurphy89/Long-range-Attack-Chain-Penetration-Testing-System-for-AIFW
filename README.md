# Long-range Attack Chain Penetration Testing System for AIFW

本项目是一个面向 AIFW（AI Firewall）场景的长程攻击链渗透测试与实验评估平台。系统以 Vulhub 靶场、Docker 多区域网络、攻击链 PoC/EXP 库、AIFW 网关和多智能体攻击生成流程为核心，支持从漏洞环境编排、攻击链执行、横向移动分析，到 AIFW 绕过实验与量化结果展示的一体化管理。

> 本仓库仅用于授权安全研究、课程设计和靶场实验。请勿在未授权目标上运行漏洞利用脚本或自动化攻击流程。

## 项目目标

- 构建可视化的 Vulhub 漏洞靶场管理系统，统一启动、停止和查看漏洞容器。
- 将漏洞容器划分为 External、DMZ、Intranet、Database 等网络区域，模拟企业多层网络环境。
- 管理 RCE、SQL 注入、任意文件读取等攻击链脚本，并支持在目标容器上执行 PoC/EXP。
- 引入 AIFW/ModSecurity 网关，对目标服务进行拦截、审计、日志分析和规则调整。
- 通过 AI Agent 生成 payload、辅助构建利用脚本，并评估 AIFW 对抗与绕过效果。
- 沉淀攻击链实验数据，提供 POV 构建准确率、EXP 构建准确率、AIFW 绕过成功率等量化指标。

## 核心功能

### 1. 漏洞靶场管理

- 自动扫描 Vulhub 漏洞目录，识别应用、CVE 编号和 docker-compose 配置。
- 支持按网络区域启动漏洞环境，并自动处理端口映射和 Docker 网络。
- 展示容器运行状态、服务端口、所属区域和攻击成功标记。

### 2. 多区域网络拓扑

- 默认网络区域包括 External、DMZ、Intranet、Database 和 AIFW Gateway。
- 支持容器拓扑可视化、节点连接、横向移动路径展示和攻击链报告生成。
- 支持本地脚本攻击、跳板攻击、交互式命令执行和攻击结果验证。

### 3. 攻击链库

- `attack-chains/` 保存按漏洞类别组织的 Go/Python 利用脚本。
- 前端提供攻击链代码查看、编辑、复制、运行和跨平台编译入口。
- 后端支持基于容器 ID 的本地执行、远程执行和自定义命令执行。

### 4. AIFW 防护与对抗实验

- 支持部署 ModSecurity AIFW 网关，并为目标服务添加拦截规则。
- 支持区域级自动拦截、目标级代理转发、审计日志读取和日志清理。
- 支持 LLM Controller Agent 分析 WAF 日志并输出规则调整动作。
- 支持攻击 Agent 发起提示词注入、日志投毒、链式升级等对抗策略。

### 5. Payload Mutator

- 提供 Base64、Hex、Unicode、URL、双重 URL 编码等 AIFW 绕过变换。
- 提供 SQL 注释插入、大小写切换、上下文逃逸、token smuggling 等 AI 攻击变体。
- 可用于快速构造对抗 payload，辅助测试规则与智能体鲁棒性。

### 6. 实验数据看板

- `backend/app/experiment_data/results.json` 保存实验样本与多轮测试结果。
- 前端 Experiment 页面展示场景检索、分类对比、雷达图、逐场景指标和成功率统计。
- 适合用于论文实验、系统评估和 AIFW 防护效果对比。

## 技术架构

```text
vulhub-manager
├── backend/                  # FastAPI 后端服务
│   ├── app/api/              # REST API 路由
│   ├── app/services/         # Docker、AIFW、Agent、报告、向量检索等服务
│   ├── app/core/config.py    # 路径、网络、LLM 与 Go 环境配置
│   ├── app/experiment_data/  # 实验数据集
│   └── targetzone_history/   # 攻击链报告历史
├── frontend/                 # Next.js 前端
│   ├── app/                  # Dashboard、TargetZone、AIFW、Agent、Experiment 等页面
│   ├── components/           # 导航栏、拓扑图、漏洞卡片、网络配置组件
│   └── lib/api.ts            # 前后端 API 封装
├── attack-chains/            # 漏洞利用脚本与攻击链样例
├── aifw/                     # ModSecurity、ML-based WAF、waf-brain 等 AIFW 组件
├── modsec_dir/               # ModSecurity 配置
├── tools/                    # 调试、扫描与辅助工具
└── requirements.txt          # Python 依赖
```

## 页面模块

- `Vulnerabilities`：漏洞靶场列表、漏洞详情、启动/停止环境。
- `Dashboard`：Docker 网络和分区容器运行状态管理。
- `TargetZone`：多区域拓扑、横向移动攻击、节点控制和攻击报告生成。
- `Attack Chains`：攻击链脚本库、脚本编辑、执行和构建。
- `AI Agent`：基于漏洞上下文生成 payload 或攻击报告。
- `AIFW`：AIFW 部署、拦截规则、日志分析和对抗测试。
- `Mutator`：payload 编码变换与提示词攻击变体生成。
- `Experiment`：长程攻击链实验结果统计与可视化。

## 环境要求

- Windows 或 Linux 主机
- Python 3.11+
- Node.js 18+
- Docker Desktop / Docker Engine
- Docker Compose v2
- Go 1.23+（用于部分 Go 攻击链脚本编译）

如需使用 LLM 相关能力，建议通过环境变量配置模型服务：

```bash
OPENAI_API_KEY=your_api_key
OPENAI_BASE_URL=https://api.example.com/v1
OPENAI_MODEL_NAME=your_model
VULHUB_ROOT=/path/to/vulhub
ATTACK_CHAINS_ROOT=/path/to/attack-chains
AIFW_ROOT=/path/to/aifw
GOROOT=/path/to/go
```

## 本地运行

### 1. 启动后端

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r ../requirements.txt
python run.py
```

Windows PowerShell 可使用：

```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r ..\requirements.txt
python run.py
```

后端默认监听：

```text
http://localhost:8000
```

### 2. 启动前端

```bash
cd frontend
npm install
npm run dev
```

前端默认监听：

```text
http://localhost:30001
```

## 典型使用流程

1. 在 `Dashboard` 中创建默认 Docker 网络并确认分区状态。
2. 在 `Vulnerabilities` 中选择漏洞环境，按目标区域启动容器。
3. 在 `TargetZone` 中查看拓扑，选择入口节点并执行本地或横向攻击。
4. 在 `AIFW` 中部署防护网关，为目标服务添加拦截规则并读取审计日志。
5. 在 `AI Agent` 或 `Mutator` 中生成 payload 变体，测试对 AIFW 的绕过能力。
6. 在 `Experiment` 中查看不同漏洞类别和攻击链场景下的实验统计结果。
7. 在 `TargetZone` 中生成攻击链报告，用于审计、复现实验或论文附录。

## 数据与报告

- 实验结果数据：`backend/app/experiment_data/results.json`
- AIFW 运行状态：`backend/app/services/aifw_state.json`
- 攻击报告历史：`backend/targetzone_history/`
- Agent 历史记录：`backend/app/agent_history/agent_history.json`

## 注意事项

- Docker 网络、容器路由和 AIFW 拦截规则会修改本机 Docker 环境，建议在独立实验机或虚拟机中运行。
- 项目中包含漏洞利用脚本和攻击 payload，仅适用于授权靶场。
- LLM API Key、靶场地址和本机路径建议使用环境变量或本地配置，不建议提交真实密钥。
- 若部分 Go 脚本无法编译，请检查 `GOROOT` 和系统 `PATH`。
