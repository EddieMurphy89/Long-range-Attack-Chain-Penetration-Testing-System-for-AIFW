"use client";
import { useState, useEffect, useCallback, useRef } from "react";
import {
    Shield, Play, Square, RefreshCw, Trash2, Brain,
    Eye, EyeOff, Settings,
    Crosshair, Route, Zap, Plus, X, Layers, Activity,
    AlertTriangle, Swords, CheckCircle2, XCircle, Loader2
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────
interface AIFWStatus {
    running: boolean;
    container_status: string;
    enabled: boolean;
    dmz_ip?: string;
    internal_ip?: string;
    intercept_rules?: string[];
    mode?: string;
    engine?: string;
    agent_enabled?: boolean;
}

interface InterceptRule {
    target: string;
    local_port: number;
}

// ── LLM Presets ────────────────────────────────────────────────
const LLM_PRESETS: Record<string, { url: string; model: string }> = {
    "Kimi (Moonshot)": { url: "https://api.moonshot.cn/v1/chat/completions", model: "moonshot-v1-auto" },
    "GPT-4o Mini": { url: "https://api.openai.com/v1/chat/completions", model: "gpt-4o-mini" },
    "GPT-4o": { url: "https://api.openai.com/v1/chat/completions", model: "gpt-4o" },
    "GPT-3.5 Turbo": { url: "https://api.openai.com/v1/chat/completions", model: "gpt-3.5-turbo" },
    "Claude 3.5": { url: "https://api.anthropic.com/v1/messages", model: "claude-3-5-sonnet-20241022" },
    "DeepSeek V3": { url: "https://api.deepseek.com/v1/chat/completions", model: "deepseek-chat" },
    "Qwen Max": { url: "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions", model: "qwen-max" },
    "GLM-5 (智谱)": { url: "https://open.bigmodel.cn/api/paas/v4/chat/completions", model: "glm-5" },
    "Custom": { url: "", model: "" },
};

export default function AIFWPage() {
    // ── State ──────────────────────────────────────────────────
    const [status, setStatus] = useState<AIFWStatus | null>(null);
    const [statusLoading, setStatusLoading] = useState(false);
    const [deploying, setDeploying] = useState(false);
    const [stopping, setStopping] = useState(false);

    const [mode, setMode] = useState("DetectionOnly");
    const [engine, setEngine] = useState("modsecurity");

    // Intercept rules
    const [rules, setRules] = useState<InterceptRule[]>([]);
    const [newTargetIp, setNewTargetIp] = useState("");
    const [newTargetPort, setNewTargetPort] = useState("");

    // LLM config dialog
    const [showLlmDialog, setShowLlmDialog] = useState(false);
    const [llmPreset, setLlmPreset] = useState("Kimi (Moonshot)");
    const [llmApiUrl, setLlmApiUrl] = useState(LLM_PRESETS["Kimi (Moonshot)"].url);
    const [llmModel, setLlmModel] = useState(LLM_PRESETS["Kimi (Moonshot)"].model);
    const [llmApiKey, setLlmApiKey] = useState("");
    const [showApiKey, setShowApiKey] = useState(false);

    // LLM config save feedback
    const [configSaving, setConfigSaving] = useState(false);
    const [configSaveMsg, setConfigSaveMsg] = useState<{ ok: boolean; text: string } | null>(null);

    // Controller test
    const [testRunning, setTestRunning] = useState(false);
    const [testResult, setTestResult] = useState<{
        llm_ok: boolean; llm_msg: string; llm_model: string;
        container_ok: boolean; container_msg: string; current_mode: string;
    } | null>(null);

    // Logs
    const [logs, setLogs] = useState<any[]>([]);
    const [rawLog, setRawLog] = useState("");
    const [showRaw, setShowRaw] = useState(false);
    const [logsLoading, setLogsLoading] = useState(false);

    // Attack LLM config (independent from controller LLM)
    const [atkLlmPreset, setAtkLlmPreset] = useState("GLM-5 (智谱)");
    const [atkLlmApiUrl, setAtkLlmApiUrl] = useState(LLM_PRESETS["GLM-5 (智谱)"].url);
    const [atkLlmModel, setAtkLlmModel] = useState(LLM_PRESETS["GLM-5 (智谱)"].model);
    const [atkLlmApiKey, setAtkLlmApiKey] = useState("");
    const [showAtkApiKey, setShowAtkApiKey] = useState(false);

    // Attack LLM save/test
    const [atkConfigSaving, setAtkConfigSaving] = useState(false);
    const [atkConfigSaveMsg, setAtkConfigSaveMsg] = useState<{ ok: boolean; text: string } | null>(null);
    const [atkTestRunning, setAtkTestRunning] = useState(false);
    const [atkTestResult, setAtkTestResult] = useState<{ ok: boolean; msg: string } | null>(null);

    // Controller Agent logs
    const [controllerLogs, setControllerLogs] = useState<string[]>([]);
    const controllerLogEndRef = useRef<HTMLDivElement | null>(null);

    // AIFW Attack Agent
    const [attackRunning, setAttackRunning] = useState(false);
    const [attackLogs, setAttackLogs] = useState<string[]>([]);
    const [attackResults, setAttackResults] = useState<any[]>([]);
    const [attackStatus, setAttackStatus] = useState("");
    const [attackTargetUrl, setAttackTargetUrl] = useState("");
    const [keepFirewallState, setKeepFirewallState] = useState(true);
    const [firewallDisabled, setFirewallDisabled] = useState<boolean | null>(null);
    const [firewallWeakened, setFirewallWeakened] = useState(false);
    const [finalMode, setFinalMode] = useState("");
    const [initialMode, setInitialMode] = useState("");
    const attackPollRef = useRef<ReturnType<typeof setInterval> | null>(null);
    const attackSeenRunning = useRef(false);
    const STRATEGY_OPTIONS = [
        { key: "direct_injection", label: "直接提示词注入" },
        { key: "role_hijacking", label: "角色劫持" },
        { key: "semantic_dilution", label: "语义稀释 + 隐蔽注入" },
        { key: "output_format_manipulation", label: "输出格式操控" },
        { key: "chain_escalation", label: "链式升级攻击" },
        { key: "llm_adaptive", label: "LLM 自适应攻击" },
    ];
    const [selectedStrategies, setSelectedStrategies] = useState<string[]>(
        STRATEGY_OPTIONS.map(s => s.key)
    );

    // ── Fetchers ───────────────────────────────────────────────
    const fetchStatus = useCallback(async () => {
        setStatusLoading(true);
        try {
            const res = await fetch("/api/aifw/status");
            const data = await res.json();
            setStatus(data);
            // Sync mode and engine from server when AIFW is running (reflects actual deployment)
            // When not running, keep user's local selection for the deploy form
            if (data.running) {
                if (data.mode) setMode(data.mode);
                if (data.engine) setEngine(data.engine);
            }
        } catch { setStatus(null); }
        setStatusLoading(false);
    }, []);

    const fetchRules = useCallback(async () => {
        try {
            const res = await fetch("/api/aifw/intercept/rules");
            const data = await res.json();
            setRules(data.rules || []);
        } catch { }
    }, []);

    useEffect(() => {
        fetchStatus();
        fetchRules();
    }, [fetchStatus, fetchRules]);

    // ── Handlers ───────────────────────────────────────────────
    const [deployError, setDeployError] = useState("");

    const handleDeploy = async () => {
        setDeploying(true);
        setDeployError("");
        try {
            const res = await fetch("/api/aifw/deploy", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ mode: mode, engine: engine })
            });
            const data = await res.json();
            if (!res.ok) {
                const msg = data?.detail || data?.message || `部署失败 (HTTP ${res.status})`;
                setDeployError(msg);
                alert(`部署失败: ${msg}`);
            } else {
                fetchStatus(); fetchRules();
            }
        } catch (e: any) {
            const msg = `网络错误: ${e.message}`;
            setDeployError(msg);
            alert(msg);
        }
        setDeploying(false);
    };

    const handleStop = async () => {
        setStopping(true);
        try {
            const res = await fetch("/api/aifw/stop", { method: "POST" });
            const data = await res.json();
            if (!res.ok) {
                alert(`停止失败: ${data?.detail || data?.message || `HTTP ${res.status}`}`);
            } else {
                fetchStatus(); setRules([]);
            }
        } catch (e: any) {
            alert(`网络错误: ${e.message}`);
        }
        setStopping(false);
    };

    const handleAddRule = async () => {
        if (!newTargetIp || !newTargetPort) return;
        try {
            await fetch("/api/aifw/intercept", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ target_ip: newTargetIp, target_port: newTargetPort }),
            });
            fetchRules(); setNewTargetIp(""); setNewTargetPort("");
        } catch { }
    };

    const handleRemoveRule = async (target: string) => {
        const [ip, port] = target.split(":");
        try {
            await fetch(`/api/aifw/intercept?target_ip=${ip}&target_port=${port}`, { method: "DELETE" });
            fetchRules();
        } catch { }
    };

    const handleSetupRouting = async () => {
        try {
            const res = await fetch("/api/aifw/routing/setup", { method: "POST" });
            const data = await res.json();
            alert(data.message || "Routing configured");
        } catch { }
    };

    const handleZoneIntercept = async () => {
        try {
            const res = await fetch("/api/aifw/intercept/zone", { method: "POST" });
            const data = await res.json();
            alert(data.message || "Zone intercept configured");
            fetchRules();
        } catch { }
    };

    const handleSaveConfig = async () => {
        setConfigSaving(true);
        setConfigSaveMsg(null);
        try {
            const res = await fetch("/api/aifw/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ llm_api_url: llmApiUrl, llm_api_key: llmApiKey, llm_model: llmModel, mode }),
            });
            const data = await res.json();
            if (res.ok && data.status === "success") {
                setConfigSaveMsg({ ok: true, text: `配置已保存 (${(data.updated || []).join(", ")})` });
            } else {
                setConfigSaveMsg({ ok: false, text: data.message || data.detail || "保存失败" });
            }
        } catch (e: any) {
            setConfigSaveMsg({ ok: false, text: `网络错误: ${e.message}` });
        }
        setConfigSaving(false);
        setTimeout(() => setConfigSaveMsg(null), 4000);
    };

    const handleTestController = async () => {
        setTestRunning(true);
        setTestResult(null);
        try {
            const res = await fetch("/api/aifw/config/test", { method: "POST" });
            const data = await res.json();
            setTestResult(data);
        } catch (e: any) {
            setTestResult({
                llm_ok: false, llm_msg: `网络错误: ${e.message}`, llm_model: "",
                container_ok: false, container_msg: "请求失败", current_mode: "",
            });
        }
        setTestRunning(false);
        fetchControllerLogs();
    };

    const handleToggleAgent = async () => {
        const newVal = !(status?.agent_enabled ?? false);
        try {
            const res = await fetch(`/api/aifw/agent/toggle?enabled=${newVal}`, { method: "POST" });
            const data = await res.json();
            if (data.status === "success") fetchStatus();
        } catch { }
    };

    const fetchLogs = async () => {
        setLogsLoading(true);
        try {
            const res = await fetch("/api/aifw/logs?tail=200");
            const data = await res.json();
            setLogs(data.entries || []); setRawLog(data.raw || "");
        } catch { }
        setLogsLoading(false);
    };

    const clearLogs = async () => {
        try { await fetch("/api/aifw/logs/clear", { method: "POST" }); setLogs([]); setRawLog(""); } catch { }
    };

    const matchPreset = (url: string, model: string, fallback: string) => {
        const exact = Object.entries(LLM_PRESETS).find(([, v]) => v.url === url && v.model === model);
        if (exact) return exact[0];
        const byUrl = Object.entries(LLM_PRESETS).find(([k, v]) => k !== "Custom" && v.url === url);
        return byUrl ? byUrl[0] : (url || model ? "Custom" : fallback);
    };

    const fetchLlmConfig = useCallback(async () => {
        try {
            const res = await fetch("/api/aifw/config");
            const data = await res.json();
            // Controller LLM
            if (data.llm_api_url) setLlmApiUrl(data.llm_api_url);
            if (data.llm_model) setLlmModel(data.llm_model);
            setLlmPreset(matchPreset(data.llm_api_url, data.llm_model, "Kimi (Moonshot)"));
            // Attack LLM
            if (data.atk_llm_api_url) setAtkLlmApiUrl(data.atk_llm_api_url);
            if (data.atk_llm_model) setAtkLlmModel(data.atk_llm_model);
            if (data.atk_llm_api_key && !data.atk_llm_api_key.includes("****")) setAtkLlmApiKey(data.atk_llm_api_key);
            setAtkLlmPreset(matchPreset(data.atk_llm_api_url, data.atk_llm_model, "GLM-5 (智谱)"));
        } catch { }
    }, []);

    useEffect(() => {
        if (showLlmDialog) fetchLlmConfig();
    }, [showLlmDialog, fetchLlmConfig]);

    const handlePresetChange = (name: string) => {
        setLlmPreset(name);
        const p = LLM_PRESETS[name];
        if (p && name !== "Custom") { setLlmApiUrl(p.url); setLlmModel(p.model); }
    };

    const handleAtkPresetChange = (name: string) => {
        setAtkLlmPreset(name);
        const p = LLM_PRESETS[name];
        if (p && name !== "Custom") { setAtkLlmApiUrl(p.url); setAtkLlmModel(p.model); }
    };

    const handleSaveAtkConfig = async () => {
        setAtkConfigSaving(true);
        setAtkConfigSaveMsg(null);
        try {
            const res = await fetch("/api/aifw/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ atk_llm_api_url: atkLlmApiUrl, atk_llm_api_key: atkLlmApiKey, atk_llm_model: atkLlmModel }),
            });
            const data = await res.json();
            if (res.ok && data.status === "success") {
                setAtkConfigSaveMsg({ ok: true, text: "攻击 LLM 配置已保存" });
            } else {
                setAtkConfigSaveMsg({ ok: false, text: data.message || "保存失败" });
            }
        } catch (e: any) {
            setAtkConfigSaveMsg({ ok: false, text: `网络错误: ${e.message}` });
        }
        setAtkConfigSaving(false);
        setTimeout(() => setAtkConfigSaveMsg(null), 4000);
    };

    const handleTestAttackLlm = async () => {
        setAtkTestRunning(true);
        setAtkTestResult(null);
        try {
            const params = new URLSearchParams({ api_url: atkLlmApiUrl, api_key: atkLlmApiKey, model: atkLlmModel });
            const res = await fetch(`/api/aifw/config/test-attack?${params}`, { method: "POST" });
            const data = await res.json();
            setAtkTestResult(data);
        } catch (e: any) {
            setAtkTestResult({ ok: false, msg: `网络错误: ${e.message}` });
        }
        setAtkTestRunning(false);
    };

    const fetchControllerLogs = useCallback(async () => {
        try {
            const res = await fetch("/api/aifw/controller/logs");
            const data = await res.json();
            setControllerLogs(data.logs || []);
        } catch { }
    }, []);

    const clearControllerLogs = async () => {
        try {
            await fetch("/api/aifw/controller/logs/clear", { method: "POST" });
            setControllerLogs([]);
        } catch { }
    };

    const toggleStrategy = (key: string) => {
        setSelectedStrategies(prev =>
            prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
        );
    };

    const pollAttackState = useCallback(async () => {
        try {
            const res = await fetch("/api/aifw/attack/state");
            const data = await res.json();
            if (data.logs?.length) setAttackLogs(data.logs);
            if (data.status) setAttackStatus(data.status);
            if (data.results?.length) setAttackResults(data.results);
            if (data.running) attackSeenRunning.current = true;
            if (!data.running && attackSeenRunning.current && attackPollRef.current) {
                clearInterval(attackPollRef.current);
                attackPollRef.current = null;
                setAttackRunning(false);
                setAttackStatus(data.results?.length ? "攻击完成" : "");
                setFirewallDisabled(data.firewall_disabled ?? false);
                setFirewallWeakened(data.firewall_weakened ?? false);
                setFinalMode(data.final_mode || "");
                setInitialMode(data.initial_mode || "");
                fetchStatus();
                fetchControllerLogs();
            }
        } catch { }
    }, [fetchStatus, fetchControllerLogs]);

    const handleLaunchAttack = async () => {
        setAttackRunning(true);
        setAttackLogs([]);
        setAttackResults([]);
        setAttackStatus("启动中...");
        setFirewallDisabled(null);
        setFirewallWeakened(false);
        setFinalMode("");
        setInitialMode("");
        attackSeenRunning.current = false;

        if (attackPollRef.current) clearInterval(attackPollRef.current);

        try {
            const res = await fetch("/api/agent/aifw-attack", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    target_url: attackTargetUrl || undefined,
                    strategies: selectedStrategies.length > 0 ? selectedStrategies : undefined,
                    api_key: atkLlmApiKey || undefined,
                    base_url: atkLlmApiUrl || undefined,
                    model_name: atkLlmModel || undefined,
                    keep_state: keepFirewallState,
                }),
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({ detail: "请求失败" }));
                setAttackLogs([`[ERROR] ${err.detail || "启动攻击失败"}`]);
                setAttackRunning(false);
                return;
            }
        } catch (e: any) {
            setAttackLogs([`[ERROR] ${e.message}`]);
            setAttackRunning(false);
            return;
        }

        attackPollRef.current = setInterval(pollAttackState, 2000);
    };

    const handleStopAttack = async () => {
        try { await fetch("/api/aifw/attack/cancel", { method: "POST" }); } catch {}
        if (attackPollRef.current) { clearInterval(attackPollRef.current); attackPollRef.current = null; }
        setAttackRunning(false);
        setAttackStatus("已停止");
    };

    useEffect(() => {
        return () => { if (attackPollRef.current) clearInterval(attackPollRef.current); };
    }, []);


    useEffect(() => {
        if (showLlmDialog) fetchControllerLogs();
    }, [showLlmDialog, fetchControllerLogs]);

    // ── Render ─────────────────────────────────────────────────
    const isRunning = status?.running ?? false;

    return (
        <div className="container mx-auto px-4 py-8">
            {/* ═══ Header ═══════════════════════════════════════════ */}
            <div className="mb-8">
                <div className="flex items-center gap-3 mb-2">
                    <span className="inline-flex items-center justify-center w-11 h-11 rounded-2xl bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300">
                        <Shield className="w-6 h-6" />
                    </span>
                    <div>
                        <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white">AI Firewall</h1>
                        <p className="text-slate-500 dark:text-slate-400">提供网络层透明流量拦截、智能分析与防护策略联动的 AI 防火墙中间件能力。</p>
                    </div>
                </div>
            </div>

            {/* ═══ Status + Deploy Row ═══════════════════════════════ */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">

                {/* Status Card */}
                <div className="lg:col-span-2 bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden">
                    <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100 dark:border-slate-800">
                        <h2 className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                            <Activity className="w-4 h-4 text-blue-500" /> 网关状态
                        </h2>
                        <button onClick={fetchStatus}
                            className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 flex items-center gap-1 transition-colors">
                            <RefreshCw className={`w-3.5 h-3.5 ${statusLoading ? "animate-spin" : ""}`} /> 刷新
                        </button>
                    </div>
                    <div className="px-5 py-4 grid grid-cols-2 md:grid-cols-5 gap-4">
                        <div>
                            <p className="text-xs text-slate-400 dark:text-slate-500 mb-1">运行状态</p>
                            <div className="flex items-center gap-2">
                                <span className={`w-2 h-2 rounded-full ${isRunning ? "bg-emerald-400 shadow-sm shadow-emerald-400/50" : "bg-slate-300 dark:bg-slate-600"}`} />
                                <span className={`font-semibold text-sm ${isRunning ? "text-emerald-600 dark:text-emerald-400" : "text-slate-500 dark:text-slate-400"}`}>
                                    {isRunning ? "运行中" : "未运行"}
                                </span>
                            </div>
                        </div>
                        <div>
                            <p className="text-xs text-slate-400 dark:text-slate-500 mb-1">检测模式</p>
                            <span className={`inline-block text-xs font-medium px-2 py-0.5 rounded-full ${(status?.mode || mode) === "On"
                                ? "bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 ring-1 ring-red-200 dark:ring-red-500/20"
                                : "bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 ring-1 ring-blue-200 dark:ring-blue-500/20"
                                }`}>
                                {(status?.mode || mode) === "On" ? "拦截模式" : "仅检测"}
                            </span>
                        </div>
                        <div>
                            <p className="text-xs text-slate-400 dark:text-slate-500 mb-1">当前引擎</p>
                            <span className="inline-block text-xs font-medium px-2 py-0.5 rounded-full bg-purple-50 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400 ring-1 ring-purple-200 dark:ring-purple-500/20">
                                {(status?.engine || engine) === 'ml-based-waf' ? 'ML-based-WAF' : ((status?.engine || engine) === 'waf-brain' ? 'WAF-Brain' : 'ModSecurity')}
                            </span>
                        </div>
                        <div>
                            <p className="text-xs text-slate-400 dark:text-slate-500 mb-1">DMZ 地址</p>
                            <p className="font-mono text-sm text-slate-700 dark:text-slate-300">{status?.dmz_ip || "—"}</p>
                        </div>
                        <div>
                            <p className="text-xs text-slate-400 dark:text-slate-500 mb-1">内网地址</p>
                            <p className="font-mono text-sm text-slate-700 dark:text-slate-300">{status?.internal_ip || "—"}</p>
                        </div>
                    </div>
                </div>

                {/* Deploy Card */}
                <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden">
                    <div className="px-5 py-4 border-b border-slate-100 dark:border-slate-800">
                        <h2 className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                            <Settings className="w-4 h-4 text-slate-400" /> 部署控制
                        </h2>
                    </div>
                    <div className="px-5 py-4 space-y-3">
                        <div>
                            <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">拦截引擎构建</label>
                            <select value={engine} onChange={e => setEngine(e.target.value)} disabled={isRunning}
                                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:opacity-50 transition-all mb-3">
                                <option value="modsecurity">ModSecurity (传统规则引擎)</option>
                                <option value="waf-brain">WAF-Brain (机器学习深度预测模型)</option>
                                <option value="ml-based-waf">ML-based-WAF (支持拦截的机器学习被动监听器)</option>
                            </select>
                        </div>
                        <div>
                            <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">检测模式</label>
                            <select value={mode} onChange={e => setMode(e.target.value)}
                                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all">
                                <option value="DetectionOnly">DetectionOnly — 仅记录不拦截</option>
                                <option value="On">On — 检测并拦截攻击</option>
                            </select>
                        </div>
                        <div className="pt-1">
                            {!isRunning ? (
                                <button onClick={handleDeploy} disabled={deploying}
                                    className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-blue-500 to-indigo-600 hover:from-blue-600 hover:to-indigo-700 text-white px-4 py-2.5 rounded-lg text-sm font-medium shadow-sm shadow-blue-500/20 disabled:opacity-50 transition-all">
                                    <Play className="w-4 h-4" /> {deploying ? "部署中…" : "部署 AIFW 网关"}
                                </button>
                            ) : (
                                <button onClick={handleStop} disabled={stopping}
                                    className="w-full flex items-center justify-center gap-2 bg-slate-100 dark:bg-slate-800 hover:bg-red-50 dark:hover:bg-red-500/10 text-slate-600 dark:text-slate-300 hover:text-red-600 dark:hover:text-red-400 px-4 py-2.5 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 hover:border-red-200 dark:hover:border-red-500/30 disabled:opacity-50 transition-all">
                                    <Square className="w-4 h-4" /> {stopping ? "停止中…" : "停止 AIFW"}
                                </button>
                            )}
                        </div>
                        {deployError && (
                            <div className="flex items-start gap-2 text-xs text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-500/10 rounded-lg p-3 ring-1 ring-red-200 dark:ring-red-500/20 break-all">
                                <AlertTriangle className="w-3.5 h-3.5 mt-0.5 flex-shrink-0" />
                                <span>{deployError}</span>
                            </div>
                        )}
                        {engine === "modsecurity" && isRunning && (
                            <button onClick={() => setShowLlmDialog(true)}
                                className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-purple-500 to-indigo-600 hover:from-purple-600 hover:to-indigo-700 text-white px-4 py-2.5 rounded-lg text-sm font-medium shadow-sm shadow-purple-500/20 transition-all">
                                <Brain className="w-4 h-4" /> LLM 智能管控
                            </button>
                        )}
                    </div>
                </div>
            </div>

            {/* ═══ Intercept Rules ═══════════════════════════════════ */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm mb-6 overflow-hidden">
                <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100 dark:border-slate-800">
                    <h2 className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                        <Crosshair className="w-4 h-4 text-amber-500" /> 拦截规则
                        {rules.length > 0 && (
                            <span className="ml-1 text-xs font-normal bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 px-2 py-0.5 rounded-full ring-1 ring-amber-200 dark:ring-amber-500/20">
                                {rules.length} 条活跃
                            </span>
                        )}
                    </h2>
                    <div className="flex gap-2">
                        <button onClick={handleZoneIntercept} disabled={!isRunning}
                            className="text-xs font-medium bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 hover:bg-amber-100 dark:hover:bg-amber-500/20 px-3 py-1.5 rounded-lg flex items-center gap-1.5 disabled:opacity-40 ring-1 ring-amber-200 dark:ring-amber-500/20 transition-colors">
                            <Layers className="w-3.5 h-3.5" /> 一键拦截全区域
                        </button>
                        <button onClick={handleSetupRouting} disabled={!isRunning}
                            className="text-xs font-medium bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-500/20 px-3 py-1.5 rounded-lg flex items-center gap-1.5 disabled:opacity-40 ring-1 ring-blue-200 dark:ring-blue-500/20 transition-colors">
                            <Route className="w-3.5 h-3.5" /> 配置路由
                        </button>
                    </div>
                </div>

                <div className="px-5 py-4">
                    <p className="text-xs text-slate-400 dark:text-slate-500 mb-4">
                        部署 AIFW 后自动拦截全部区域容器流量。启动新容器或执行攻击时也会自动添加规则。也可在此手动添加额外拦截目标。
                    </p>

                    {/* Add rule form */}
                    <div className="flex gap-2 mb-4">
                        <input value={newTargetIp} onChange={e => setNewTargetIp(e.target.value)}
                            placeholder="目标 IP，如 192.168.6.2" disabled={!isRunning}
                            className="flex-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:opacity-40 transition-all" />
                        <input value={newTargetPort} onChange={e => setNewTargetPort(e.target.value)}
                            placeholder="端口" disabled={!isRunning}
                            className="w-24 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 disabled:opacity-40 transition-all" />
                        <button onClick={handleAddRule} disabled={!isRunning || !newTargetIp || !newTargetPort}
                            className="flex items-center gap-1 bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-40 transition-colors shadow-sm">
                            <Plus className="w-4 h-4" /> 添加
                        </button>
                    </div>

                    {/* Rules list */}
                    {rules.length === 0 ? (
                        <div className="text-center py-8 text-slate-400 dark:text-slate-500">
                            <Crosshair className="w-8 h-8 mx-auto mb-2 opacity-30" />
                            <p className="text-sm">暂无拦截规则</p>
                            <p className="text-xs mt-1">部署 AIFW 后将自动添加区域级拦截规则</p>
                        </div>
                    ) : (
                        <div className="space-y-1.5">
                            {rules.map((r) => (
                                <div key={r.target}
                                    className="flex items-center justify-between bg-slate-50 dark:bg-slate-800/50 rounded-lg px-4 py-2.5 group hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
                                    <div className="flex items-center gap-3">
                                        <span className="w-1.5 h-1.5 rounded-full bg-amber-400" />
                                        <span className="font-mono text-sm text-slate-700 dark:text-slate-300">{r.target}</span>
                                        <span className="text-xs text-slate-400 dark:text-slate-500">→ AIFW :{r.local_port}</span>
                                    </div>
                                    <button onClick={() => handleRemoveRule(r.target)}
                                        className="text-slate-300 dark:text-slate-600 hover:text-red-500 dark:hover:text-red-400 opacity-0 group-hover:opacity-100 transition-all">
                                        <X className="w-4 h-4" />
                                    </button>
                                </div>
                            ))}
                        </div>
                    )}
                </div>
            </div>


            {/* ═══ Audit Logs ═══════════════════════════════════════ */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm mb-6 overflow-hidden">
                <div className="flex items-center justify-between px-5 py-4 border-b border-slate-100 dark:border-slate-800">
                    <h2 className="font-semibold text-slate-900 dark:text-white flex items-center gap-2">
                        <Shield className="w-4 h-4 text-emerald-500" /> 审计日志
                        {logs.length > 0 && (
                            <span className="text-xs font-normal bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 px-2 py-0.5 rounded-full ring-1 ring-emerald-200 dark:ring-emerald-500/20">
                                {logs.length} 条
                            </span>
                        )}
                    </h2>
                    <div className="flex gap-1.5">
                        <button onClick={() => setShowRaw(!showRaw)}
                            className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 px-2 py-1 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                            {showRaw ? "解析视图" : "原始视图"}
                        </button>
                        <button onClick={fetchLogs} disabled={!isRunning}
                            className="text-xs text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 px-2 py-1 rounded-md hover:bg-slate-50 dark:hover:bg-slate-800 flex items-center gap-1 disabled:opacity-40 transition-colors">
                            <RefreshCw className={`w-3 h-3 ${logsLoading ? "animate-spin" : ""}`} /> 刷新
                        </button>
                        <button onClick={clearLogs} disabled={!isRunning}
                            className="text-xs text-red-400 hover:text-red-500 px-2 py-1 rounded-md hover:bg-red-50 dark:hover:bg-red-500/10 flex items-center gap-1 disabled:opacity-40 transition-colors">
                            <Trash2 className="w-3 h-3" /> 清空
                        </button>
                    </div>
                </div>

                <div className="px-5 py-4">
                    <div className="bg-slate-50 dark:bg-slate-950 rounded-lg border border-slate-100 dark:border-slate-800 overflow-hidden">
                        {showRaw ? (
                            <pre className="p-4 max-h-80 overflow-auto whitespace-pre-wrap text-xs font-mono text-slate-600 dark:text-slate-400 leading-relaxed">{rawLog || "暂无日志"}</pre>
                        ) : logs.length === 0 ? (
                            <div className="text-center py-6 text-slate-400 dark:text-slate-500">
                                <Shield className="w-8 h-8 mx-auto mb-2 opacity-30" />
                                <p className="text-sm">暂无日志记录</p>
                                <p className="text-xs mt-1">启动 AIFW 后点击"刷新"获取审计日志</p>
                            </div>
                        ) : (
                            <div className="overflow-x-auto">
                                <table className="w-full text-left text-xs">
                                    <thead className="bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400">
                                        <tr>
                                            <th className="px-4 py-2 font-medium w-32">时间</th>
                                            <th className="px-4 py-2 font-medium w-48">流量方向</th>
                                            <th className="px-4 py-2 font-medium">攻击载荷 (Payload)</th>
                                            <th className="px-4 py-2 font-medium w-48">拦截规则</th>
                                            <th className="px-4 py-2 font-medium w-20">状态</th>
                                        </tr>
                                    </thead>
                                    <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                                        {logs.map((e, i) => {
                                            const payload = e.request_body || `${e.request_method} ${e.request_uri}`;
                                            const rule = e.rule_msg || (e.messages && e.messages.length > 0 ? "Potential Attack" : "—");
                                            const shortPayload = payload.length > 60 ? payload.substring(0, 60) + "..." : payload;

                                            // Format timestamp "dd/MMM/yyyy:HH:mm:ss +0000" -> "HH:mm:ss"
                                            let timeDisplay = e.timestamp;
                                            try {
                                                if (typeof e.timestamp === 'string' && e.timestamp.includes(':')) {
                                                    timeDisplay = e.timestamp.split(':')[1] + ":" + e.timestamp.split(':')[2] + ":" + e.timestamp.split(':')[3].split(' ')[0];
                                                }
                                            } catch { }

                                            return (
                                                <tr key={i} className="hover:bg-slate-100 dark:hover:bg-slate-800/50 transition-colors">
                                                    <td className="px-4 py-2.5 text-slate-400 font-mono whitespace-nowrap">{timeDisplay}</td>
                                                    <td className="px-4 py-2.5">
                                                        <div className="flex items-center gap-1.5 font-mono text-slate-600 dark:text-slate-300">
                                                            <span>{e.client_ip}</span>
                                                            <span className="text-slate-300">→</span>
                                                            <span title={e.target}>{e.target_ip || "Target"}</span>
                                                        </div>
                                                    </td>
                                                    <td className="px-4 py-2.5">
                                                        <code className="bg-slate-200 dark:bg-slate-800 px-1.5 py-0.5 rounded text-slate-700 dark:text-slate-300 break-all" title={payload}>
                                                            {shortPayload}
                                                        </code>
                                                    </td>
                                                    <td className="px-4 py-2.5">
                                                        {e.rule_id ? (
                                                            <div className="flex flex-col">
                                                                <span className="text-amber-600 dark:text-amber-400 font-medium truncate w-44" title={rule}>{rule}</span>
                                                                <span className="text-[10px] text-slate-400">ID: {e.rule_id}</span>
                                                            </div>
                                                        ) : (
                                                            <span className="text-slate-300 dark:text-slate-600">—</span>
                                                        )}
                                                    </td>
                                                    <td className="px-4 py-2.5">
                                                        <span className={`inline-block px-1.5 py-0.5 rounded text-[10px] font-medium ${e.status_code >= 400 && e.status_code < 500 ? "bg-red-50 text-red-600" : "bg-green-50 text-green-600"
                                                            }`}>
                                                            {e.status_code}
                                                        </span>
                                                    </td>
                                                </tr>
                                            );
                                        })}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            </div>


            {/* ═══ LLM 智能管控 Dialog ═══════════════════════════════ */}
            {showLlmDialog && (
                <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
                    <div className="absolute inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setShowLlmDialog(false)} />
                    <div className="relative w-full max-w-2xl max-h-[90vh] overflow-y-auto bg-white dark:bg-slate-900 rounded-2xl border border-slate-200 dark:border-slate-800 shadow-2xl">
                        {/* Dialog Header */}
                        <div className="sticky top-0 z-10 flex items-center justify-between px-6 py-4 border-b border-slate-100 dark:border-slate-800 bg-white dark:bg-slate-900 rounded-t-2xl">
                            <h2 className="text-lg font-bold text-slate-900 dark:text-white flex items-center gap-2">
                                <Brain className="w-5 h-5 text-purple-500" /> LLM 智能管控
                                <span className="text-xs font-normal bg-purple-50 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400 px-2 py-0.5 rounded-full ring-1 ring-purple-200 dark:ring-purple-500/20">
                                    ModSecurity
                                </span>
                            </h2>
                            <button onClick={() => setShowLlmDialog(false)}
                                className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors">
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <div className="px-6 py-5 space-y-6">
                            {/* ── LLM 配置 ── */}
                            <div className="space-y-4">
                                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                                    <Settings className="w-4 h-4 text-slate-400" /> LLM 配置
                                </h3>
                                <p className="text-xs text-slate-400 dark:text-slate-500">
                                    配置 LLM 作为 ModSecurity 的智能管理员 Agent，可自动分析日志并执行规则调整、模式切换等操作。
                                </p>
                                <div>
                                    <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">模型预设</label>
                                    <select value={llmPreset} onChange={e => handlePresetChange(e.target.value)}
                                        className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all">
                                        {Object.keys(LLM_PRESETS).map(k => <option key={k} value={k}>{k}</option>)}
                                    </select>
                                </div>
                                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div>
                                        <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">API URL</label>
                                        <input value={llmApiUrl} onChange={e => setLlmApiUrl(e.target.value)}
                                            className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all" />
                                    </div>
                                    <div>
                                        <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">模型名称</label>
                                        <input value={llmModel} onChange={e => setLlmModel(e.target.value)}
                                            className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all" />
                                    </div>
                                </div>
                                <div>
                                    <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">API Key</label>
                                    <div className="flex gap-2">
                                        <input value={llmApiKey} onChange={e => setLlmApiKey(e.target.value)}
                                            type={showApiKey ? "text" : "password"}
                                            placeholder="sk-..."
                                            className="flex-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-blue-500/20 focus:border-blue-500 transition-all" />
                                        <button onClick={() => setShowApiKey(!showApiKey)}
                                            className="px-3 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                                            {showApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                        </button>
                                    </div>
                                </div>
                                <div className="flex items-center gap-3">
                                    <button onClick={handleSaveConfig} disabled={configSaving}
                                        className="bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg text-sm font-medium shadow-sm transition-colors disabled:opacity-50 flex items-center gap-2">
                                        {configSaving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}
                                        {configSaving ? "保存中…" : "保存配置"}
                                    </button>
                                    {configSaveMsg && (
                                        <span className={`text-xs flex items-center gap-1 ${configSaveMsg.ok ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}>
                                            {configSaveMsg.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                                            {configSaveMsg.text}
                                        </span>
                                    )}
                                </div>
                            </div>

                            {/* ── Divider ── */}
                            <div className="border-t border-slate-100 dark:border-slate-800" />

                            {/* ── Controller Agent 能力面板 ── */}
                            <div className="space-y-4">
                                <div className="flex items-center justify-between">
                                    <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                                        <Brain className="w-4 h-4 text-purple-500" /> Controller Agent 能力
                                        {testResult ? (
                                            <span className={`text-xs font-normal px-2 py-0.5 rounded-full ring-1 ${
                                                testResult.llm_ok && testResult.container_ok
                                                    ? "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 ring-emerald-200 dark:ring-emerald-500/20"
                                                    : testResult.llm_ok || testResult.container_ok
                                                        ? "bg-amber-50 dark:bg-amber-500/10 text-amber-600 dark:text-amber-400 ring-amber-200 dark:ring-amber-500/20"
                                                        : "bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 ring-red-200 dark:ring-red-500/20"
                                            }`}>
                                                {testResult.llm_ok && testResult.container_ok ? "就绪" : testResult.llm_ok || testResult.container_ok ? "部分就绪" : "不可用"}
                                            </span>
                                        ) : (
                                            <span className={`text-xs font-normal px-2 py-0.5 rounded-full ring-1 ${
                                                llmApiKey
                                                    ? "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 ring-slate-200 dark:ring-slate-700"
                                                    : "bg-slate-100 dark:bg-slate-800 text-slate-400 dark:text-slate-500 ring-slate-200 dark:ring-slate-700"
                                            }`}>
                                                {llmApiKey ? "待验证" : "未配置"}
                                            </span>
                                        )}
                                    </h3>
                                    <div className="flex items-center gap-2">
                                        <button onClick={handleTestController} disabled={testRunning}
                                            className="text-xs font-medium bg-purple-50 dark:bg-purple-500/10 text-purple-600 dark:text-purple-400 hover:bg-purple-100 dark:hover:bg-purple-500/20 px-3 py-1.5 rounded-lg flex items-center gap-1.5 disabled:opacity-50 ring-1 ring-purple-200 dark:ring-purple-500/20 transition-colors">
                                            {testRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
                                            {testRunning ? "验证中…" : "验证连通性"}
                                        </button>
                                        <button onClick={handleToggleAgent}
                                            className={`text-xs font-medium px-3 py-1.5 rounded-lg flex items-center gap-1.5 ring-1 transition-colors ${
                                                status?.agent_enabled
                                                    ? "bg-emerald-50 dark:bg-emerald-500/10 text-emerald-600 dark:text-emerald-400 hover:bg-red-50 dark:hover:bg-red-500/10 hover:text-red-600 dark:hover:text-red-400 ring-emerald-200 dark:ring-emerald-500/20 hover:ring-red-200 dark:hover:ring-red-500/20"
                                                    : "bg-slate-100 dark:bg-slate-800 text-slate-500 dark:text-slate-400 hover:bg-emerald-50 dark:hover:bg-emerald-500/10 hover:text-emerald-600 dark:hover:text-emerald-400 ring-slate-200 dark:ring-slate-700 hover:ring-emerald-200 dark:hover:ring-emerald-500/20"
                                            }`}>
                                            {status?.agent_enabled
                                                ? <><Shield className="w-3.5 h-3.5" /> Agent 已启用 · 点击关闭</>
                                                : <><Square className="w-3.5 h-3.5" /> Agent 已关闭 · 点击启用</>
                                            }
                                        </button>
                                    </div>
                                </div>

                                {/* Test results */}
                                {testResult && (
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                        <div className={`flex items-start gap-3 px-4 py-3 rounded-lg border ${
                                            testResult.llm_ok
                                                ? "border-emerald-200 dark:border-emerald-500/20 bg-emerald-50 dark:bg-emerald-500/5"
                                                : "border-red-200 dark:border-red-500/20 bg-red-50 dark:bg-red-500/5"
                                        }`}>
                                            {testResult.llm_ok
                                                ? <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                                                : <XCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />}
                                            <div>
                                                <p className={`text-xs font-semibold ${testResult.llm_ok ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}`}>
                                                    LLM API
                                                </p>
                                                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5 break-all">{testResult.llm_msg}</p>
                                            </div>
                                        </div>
                                        <div className={`flex items-start gap-3 px-4 py-3 rounded-lg border ${
                                            testResult.container_ok
                                                ? "border-emerald-200 dark:border-emerald-500/20 bg-emerald-50 dark:bg-emerald-500/5"
                                                : "border-red-200 dark:border-red-500/20 bg-red-50 dark:bg-red-500/5"
                                        }`}>
                                            {testResult.container_ok
                                                ? <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 flex-shrink-0" />
                                                : <XCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />}
                                            <div>
                                                <p className={`text-xs font-semibold ${testResult.container_ok ? "text-emerald-700 dark:text-emerald-300" : "text-red-700 dark:text-red-300"}`}>
                                                    ModSecurity 容器
                                                </p>
                                                <p className="text-[11px] text-slate-500 dark:text-slate-400 mt-0.5">{testResult.container_msg}</p>
                                            </div>
                                        </div>
                                    </div>
                                )}

                                {/* Controller Agent real-time logs */}
                                <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
                                    <div className="px-4 py-2 border-b border-slate-800 flex items-center justify-between">
                                        <span className="text-xs text-slate-400 font-medium">Controller Agent Log</span>
                                        <div className="flex items-center gap-2">
                                            <span className="text-[10px] text-slate-500">{controllerLogs.length} entries</span>
                                            <button onClick={clearControllerLogs}
                                                className="text-[10px] text-slate-500 hover:text-red-400 transition-colors">
                                                清空
                                            </button>
                                        </div>
                                    </div>
                                    <div className="p-4 max-h-48 overflow-auto">
                                        {controllerLogs.length === 0 ? (
                                            <p className="text-xs text-slate-600 text-center py-2">暂无日志 — 点击「验证连通性」或发起对抗测试后日志将在此显示</p>
                                        ) : (
                                            controllerLogs.map((log, i) => (
                                                <div key={i} className={`text-xs font-mono leading-relaxed whitespace-pre-wrap mb-1 ${
                                                    log.includes("✓") ? "text-emerald-400" :
                                                    log.includes("✗") ? "text-red-400" :
                                                    log.includes("⚡") ? "text-yellow-400" :
                                                    log.includes("[Agent]") ? "text-purple-400" :
                                                    log.includes("[Test]") ? "text-cyan-400" :
                                                    "text-slate-400"
                                                }`}>
                                                    {log}
                                                </div>
                                            ))
                                        )}
                                        <div ref={controllerLogEndRef} />
                                    </div>
                                </div>

                                <p className="text-xs text-slate-400 dark:text-slate-500">
                                    上方保存的 LLM 将作为 ModSecurity 的智能管理员 Agent。对抗测试时攻击 Agent 会自动触发 Controller Agent 分析审计日志，
                                    Controller Agent 可能被注入的 payload 诱导执行以下危险操作：
                                </p>

                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                    {[
                                        { action: "SET_MODE", desc: "切换拦截模式", detail: "On / DetectionOnly / Off", color: "text-red-500" },
                                        { action: "DISABLE_RULE", desc: "禁用 CRS 规则", detail: "按规则 ID 移除检测规则", color: "text-amber-500" },
                                        { action: "ADD_EXCEPTION", desc: "添加 URI 白名单", detail: "使指定路径绕过全部检测", color: "text-orange-500" },
                                        { action: "RELOAD", desc: "重载 Nginx 配置", detail: "使配置变更立即生效", color: "text-blue-500" },
                                    ].map(t => (
                                        <div key={t.action}
                                            className="flex items-start gap-3 px-3 py-2.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800/50">
                                            <Zap className={`w-3.5 h-3.5 mt-0.5 flex-shrink-0 ${t.color}`} />
                                            <div>
                                                <p className="text-xs font-mono font-semibold text-slate-700 dark:text-slate-300">[ACTION: {t.action}]</p>
                                                <p className="text-[11px] text-slate-500 dark:text-slate-400">{t.desc} — {t.detail}</p>
                                            </div>
                                        </div>
                                    ))}
                                </div>

                                <div className="bg-purple-50/50 dark:bg-purple-500/5 rounded-lg border border-purple-100 dark:border-purple-500/10 px-4 py-3">
                                    <p className="text-xs text-purple-600 dark:text-purple-400 leading-relaxed">
                                        <strong>攻击链路：</strong>攻击 Agent 发送含 Prompt Injection 的 HTTP 请求 → ModSecurity 记录到审计日志 →
                                        Controller Agent 分析日志时读取到注入内容 → 被诱导输出 ACTION 指令 → 系统自动执行 → AIFW 防御失效
                                    </p>
                                </div>
                            </div>

                            {/* ── Divider ── */}
                            <div className="border-t border-slate-100 dark:border-slate-800" />

                            {/* ── AIFW 对抗测试 ── */}
                            <div className="space-y-4">
                                <h3 className="text-sm font-semibold text-slate-700 dark:text-slate-300 flex items-center gap-2">
                                    <Swords className="w-4 h-4 text-red-500" /> AIFW 对抗测试
                                    <span className="text-xs font-normal bg-red-50 dark:bg-red-500/10 text-red-600 dark:text-red-400 px-2 py-0.5 rounded-full ring-1 ring-red-200 dark:ring-red-500/20">
                                        Prompt Injection
                                    </span>
                                </h3>
                                <p className="text-xs text-slate-400 dark:text-slate-500">
                                    通过在 HTTP 请求中嵌入提示词注入 payload，诱导 AIFW 的 LLM 管理员 Agent 执行关闭防火墙、禁用规则等操作。
                                    攻击链：发送注入请求 → WAF 记录日志 → LLM Agent 分析日志时被注入控制 → 执行 ACTION 指令 → 防御失效。
                                </p>

                                {/* Attack LLM config */}
                                <div className="bg-red-50/50 dark:bg-red-500/5 rounded-lg border border-red-100 dark:border-red-500/10 p-4 space-y-3">
                                    <label className="text-xs font-medium text-red-600 dark:text-red-400 block">攻击驱动 LLM</label>
                                    <div>
                                        <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">模型预设</label>
                                        <select value={atkLlmPreset} onChange={e => handleAtkPresetChange(e.target.value)}
                                            className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all">
                                            {Object.keys(LLM_PRESETS).map(k => <option key={k} value={k}>{k}</option>)}
                                        </select>
                                    </div>
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                                        <div>
                                            <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">API URL</label>
                                            <input value={atkLlmApiUrl} onChange={e => setAtkLlmApiUrl(e.target.value)}
                                                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all" />
                                        </div>
                                        <div>
                                            <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">模型名称</label>
                                            <input value={atkLlmModel} onChange={e => setAtkLlmModel(e.target.value)}
                                                className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all" />
                                        </div>
                                    </div>
                                    <div>
                                        <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">API Key</label>
                                        <div className="flex gap-2">
                                            <input value={atkLlmApiKey} onChange={e => setAtkLlmApiKey(e.target.value)}
                                                type={showAtkApiKey ? "text" : "password"}
                                                placeholder="sk-..."
                                                className="flex-1 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all" />
                                            <button onClick={() => setShowAtkApiKey(!showAtkApiKey)}
                                                className="px-3 rounded-lg border border-slate-200 dark:border-slate-700 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors">
                                                {showAtkApiKey ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                                            </button>
                                        </div>
                                    </div>
                                    <div className="flex items-center gap-3 flex-wrap">
                                        <button onClick={handleSaveAtkConfig} disabled={atkConfigSaving}
                                            className="text-xs font-medium bg-blue-50 dark:bg-blue-500/10 text-blue-600 dark:text-blue-400 hover:bg-blue-100 dark:hover:bg-blue-500/20 px-3 py-1.5 rounded-lg flex items-center gap-1.5 disabled:opacity-50 ring-1 ring-blue-200 dark:ring-blue-500/20 transition-colors">
                                            {atkConfigSaving ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Settings className="w-3.5 h-3.5" />}
                                            {atkConfigSaving ? "保存中…" : "保存配置"}
                                        </button>
                                        <button onClick={handleTestAttackLlm}
                                            disabled={atkTestRunning || !atkLlmApiKey}
                                            className="text-xs font-medium bg-red-100 dark:bg-red-500/10 text-red-600 dark:text-red-400 hover:bg-red-200 dark:hover:bg-red-500/20 px-3 py-1.5 rounded-lg flex items-center gap-1.5 disabled:opacity-50 ring-1 ring-red-200 dark:ring-red-500/20 transition-colors">
                                            {atkTestRunning ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Activity className="w-3.5 h-3.5" />}
                                            {atkTestRunning ? "验证中…" : "验证连通性"}
                                        </button>
                                        {atkConfigSaveMsg && (
                                            <span className={`text-xs flex items-center gap-1 ${atkConfigSaveMsg.ok ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}>
                                                {atkConfigSaveMsg.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                                                {atkConfigSaveMsg.text}
                                            </span>
                                        )}
                                        {atkTestResult && !atkConfigSaveMsg && (
                                            <span className={`text-xs flex items-center gap-1 ${atkTestResult.ok ? "text-emerald-600 dark:text-emerald-400" : "text-red-600 dark:text-red-400"}`}>
                                                {atkTestResult.ok ? <CheckCircle2 className="w-3.5 h-3.5" /> : <XCircle className="w-3.5 h-3.5" />}
                                                {atkTestResult.msg}
                                            </span>
                                        )}
                                    </div>
                                </div>

                                {/* Target URL */}
                                <div>
                                    <label className="text-xs text-slate-400 dark:text-slate-500 block mb-1.5">目标 URL (可选，留空将使用模拟日志)</label>
                                    <input value={attackTargetUrl} onChange={e => setAttackTargetUrl(e.target.value)}
                                        placeholder="http://192.168.6.2:8080"
                                        className="w-full rounded-lg border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 px-3 py-2 text-sm text-slate-700 dark:text-slate-300 placeholder:text-slate-400 dark:placeholder:text-slate-500 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500 transition-all" />
                                </div>

                                {/* Strategy checkboxes */}
                                <div>
                                    <label className="text-xs text-slate-400 dark:text-slate-500 block mb-2">攻击策略</label>
                                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                        {STRATEGY_OPTIONS.map(s => (
                                            <label key={s.key}
                                                className={`flex items-center gap-2.5 px-3 py-2.5 rounded-lg border cursor-pointer transition-all text-sm ${
                                                    selectedStrategies.includes(s.key)
                                                        ? "border-red-300 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 text-red-700 dark:text-red-300"
                                                        : "border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-600 dark:text-slate-400 hover:border-slate-300 dark:hover:border-slate-600"
                                                }`}>
                                                <input type="checkbox" checked={selectedStrategies.includes(s.key)}
                                                    onChange={() => toggleStrategy(s.key)}
                                                    className="rounded border-slate-300 text-red-500 focus:ring-red-500/20" />
                                                {s.label}
                                            </label>
                                        ))}
                                    </div>
                                </div>

                                {/* Keep state toggle */}
                                <label className="flex items-center gap-2.5 text-sm cursor-pointer">
                                    <input type="checkbox" checked={keepFirewallState}
                                        onChange={e => setKeepFirewallState(e.target.checked)}
                                        className="rounded border-slate-300 text-red-500 focus:ring-red-500/20" />
                                    <span className="text-slate-600 dark:text-slate-400">
                                        攻击成功后<strong className="text-red-600 dark:text-red-400">保持防火墙失效状态</strong>
                                        <span className="text-xs text-slate-400 dark:text-slate-500 ml-1">(关闭后可直接在 Target Zone 发起攻击)</span>
                                    </span>
                                </label>

                                {/* Action buttons */}
                                <div className="flex gap-3 flex-wrap">
                                    <button onClick={handleLaunchAttack}
                                        disabled={attackRunning || selectedStrategies.length === 0 || !atkLlmApiKey}
                                        className="flex items-center gap-2 bg-gradient-to-r from-red-500 to-orange-600 hover:from-red-600 hover:to-orange-700 text-white px-5 py-2.5 rounded-lg text-sm font-medium shadow-sm shadow-red-500/20 disabled:opacity-50 transition-all">
                                        {attackRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Zap className="w-4 h-4" />}
                                        {attackRunning ? "攻击进行中…" : "发起攻击"}
                                    </button>
                                    <button onClick={handleStopAttack}
                                        disabled={!attackRunning}
                                        className="flex items-center gap-2 bg-slate-100 dark:bg-slate-800 hover:bg-red-50 dark:hover:bg-red-500/10 text-slate-600 dark:text-slate-300 hover:text-red-600 dark:hover:text-red-400 px-5 py-2.5 rounded-lg text-sm font-medium border border-slate-200 dark:border-slate-700 disabled:opacity-40 transition-all">
                                        <Square className="w-4 h-4" /> 停止攻击
                                    </button>
                                    {!atkLlmApiKey && !attackRunning && (
                                        <span className="text-xs text-amber-500 dark:text-amber-400 self-center">
                                            请先在上方填写攻击驱动 LLM 的 API Key
                                        </span>
                                    )}
                                </div>

                                {/* Status indicator */}
                                {attackStatus && (
                                    <div className="flex items-center gap-2 text-sm text-blue-600 dark:text-blue-400">
                                        <Loader2 className="w-4 h-4 animate-spin" /> {attackStatus}
                                    </div>
                                )}

                                {/* Attack logs */}
                                {attackLogs.length > 0 && (
                                    <div className="bg-slate-950 rounded-lg border border-slate-800 overflow-hidden">
                                        <div className="px-4 py-2 border-b border-slate-800 flex items-center justify-between">
                                            <span className="text-xs text-slate-400 font-medium">Attack Agent Log</span>
                                            <span className="text-[10px] text-slate-500">{attackLogs.length} entries</span>
                                        </div>
                                        <div className="p-4 max-h-64 overflow-auto">
                                            {attackLogs.map((log, i) => (
                                                <div key={i} className={`text-xs font-mono leading-relaxed whitespace-pre-wrap mb-1 ${
                                                    log.includes("最终目标达成") ? "text-green-400 font-bold text-sm" :
                                                    log.includes("防护已被削弱") ? "text-yellow-400 font-bold text-sm" :
                                                    log.includes("最终目标未达成") ? "text-red-400 font-bold" :
                                                    log.includes("攻击成功") ? "text-green-400 font-bold" :
                                                    log.includes("[Final]") ? "text-yellow-300 font-semibold" :
                                                    log.includes("[Adapt]") || log.includes("[LLM-Gen]") ? "text-blue-400" :
                                                    log.includes("[ERROR]") ? "text-red-400" :
                                                    log.includes("[Verify]") ? "text-yellow-400" :
                                                    log.includes("[Strategy") || log.includes("--- Round") || log.includes("--- LLM Adaptive") ? "text-cyan-400" :
                                                    log.includes("[Report]") ? "text-purple-400" :
                                                    log.includes("[Prereq]") ? "text-blue-300" :
                                                    "text-slate-400"
                                                }`}>
                                                    {log}
                                                </div>
                                            ))}
                                            
                                        </div>
                                    </div>
                                )}

                                {/* Final goal + results */}
                                {firewallDisabled !== null && (
                                    <div className="space-y-3">
                                        {/* Final goal card */}
                                        <div className={`rounded-lg border-2 p-4 ${
                                            firewallDisabled
                                                ? "border-green-400 dark:border-green-500/40 bg-gradient-to-r from-green-50 to-emerald-50 dark:from-green-500/10 dark:to-emerald-500/10"
                                                : firewallWeakened
                                                    ? "border-yellow-400 dark:border-yellow-500/40 bg-gradient-to-r from-yellow-50 to-amber-50 dark:from-yellow-500/10 dark:to-amber-500/10"
                                                    : "border-red-300 dark:border-red-500/30 bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-500/10 dark:to-orange-500/10"
                                        }`}>
                                            <div className="flex items-center gap-3">
                                                {firewallDisabled
                                                    ? <CheckCircle2 className="w-7 h-7 text-green-500 flex-shrink-0" />
                                                    : firewallWeakened
                                                        ? <AlertTriangle className="w-7 h-7 text-yellow-500 flex-shrink-0" />
                                                        : <XCircle className="w-7 h-7 text-red-500 flex-shrink-0" />
                                                }
                                                <div>
                                                    <p className={`text-base font-bold ${
                                                        firewallDisabled ? "text-green-700 dark:text-green-300"
                                                            : firewallWeakened ? "text-yellow-700 dark:text-yellow-300"
                                                                : "text-red-700 dark:text-red-300"
                                                    }`}>
                                                        {firewallDisabled
                                                            ? "最终目标达成 — 防火墙已被攻击关闭"
                                                            : firewallWeakened
                                                                ? "防火墙防护已被削弱 — 部分规则已失效"
                                                                : "最终目标未达成 — 防火墙仍在拦截"
                                                        }
                                                    </p>
                                                    <p className={`text-sm mt-0.5 ${
                                                        firewallDisabled ? "text-green-600 dark:text-green-400"
                                                            : firewallWeakened ? "text-yellow-600 dark:text-yellow-400"
                                                                : "text-red-600 dark:text-red-400"
                                                    }`}>
                                                        {initialMode && finalMode
                                                            ? `模式变化: ${initialMode} → ${finalMode}`
                                                            : `当前模式: ${finalMode || "Unknown"}`
                                                        }
                                                    </p>
                                                    {firewallDisabled && (
                                                        <p className="text-xs text-green-600 dark:text-green-400 mt-1">
                                                            防火墙拦截已失效，可直接在 Target Zone 发起漏洞利用攻击
                                                        </p>
                                                    )}
                                                    {firewallWeakened && (
                                                        <p className="text-xs text-yellow-600 dark:text-yellow-400 mt-1">
                                                            关键防护规则已被禁用或白名单已被添加，防护能力下降
                                                        </p>
                                                    )}
                                                </div>
                                            </div>
                                        </div>

                                        {/* Per-strategy breakdown */}
                                        {attackResults.length > 0 && (
                                            <div className="space-y-2">
                                                <h4 className="text-sm font-semibold text-slate-700 dark:text-slate-300">
                                                    各策略结果
                                                    <span className="ml-2 text-xs font-normal text-slate-400">
                                                        {attackResults.filter(r => r.success).length}/{attackResults.length} 种策略成功
                                                    </span>
                                                </h4>
                                                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                                                    {attackResults.map((r, i) => (
                                                        <div key={i}
                                                            className={`flex items-center gap-3 px-4 py-3 rounded-lg border ${
                                                                r.success
                                                                    ? "border-green-300 dark:border-green-500/30 bg-green-50 dark:bg-green-500/10"
                                                                    : "border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800"
                                                            }`}>
                                                            {r.success
                                                                ? <CheckCircle2 className="w-5 h-5 text-green-500 flex-shrink-0" />
                                                                : <XCircle className="w-5 h-5 text-slate-400 flex-shrink-0" />
                                                            }
                                                            <div>
                                                                <p className={`text-sm font-medium ${r.success ? "text-green-700 dark:text-green-300" : "text-slate-600 dark:text-slate-400"}`}>
                                                                    {r.name}
                                                                    {r.round && r.round > 1 && (
                                                                        <span className="ml-1.5 text-xs font-normal opacity-70">(第{r.round}轮)</span>
                                                                    )}
                                                                </p>
                                                                {r.success && r.mode_before !== r.mode_after && (
                                                                    <p className="text-xs text-green-600 dark:text-green-400">
                                                                        {r.mode_before} → {r.mode_after}
                                                                    </p>
                                                                )}
                                                                {r.success && r.actions_executed?.filter((a: any) => a.status !== "skipped").length > 0 && (
                                                                    <p className="text-xs text-green-600/80 dark:text-green-400/80">
                                                                        {r.actions_executed.filter((a: any) => a.status !== "skipped").map((a: any) => a.action).join(", ")}
                                                                    </p>
                                                                )}
                                                                {!r.success && r.reason && (
                                                                    <p className="text-xs text-slate-500 dark:text-slate-500">{r.reason}</p>
                                                                )}
                                                            </div>
                                                        </div>
                                                    ))}
                                                </div>
                                            </div>
                                        )}
                                    </div>
                                )}
                            </div>
                        </div>
                    </div>
                </div>
            )}
        </div>
    );
}
