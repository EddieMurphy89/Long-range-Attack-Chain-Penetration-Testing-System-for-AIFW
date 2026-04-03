"use client";

import React, { FormEvent, useEffect, useMemo, useState } from "react";
import {
    FlaskConical,
    Search,
    ArrowUpDown,
    CheckCircle2,
    XCircle,
    BarChart3,
    Radar as RadarIcon,
    Table2,
    ChevronUp,
    ChevronDown,
    ShieldOff,
    Crosshair,
    Binary,
    Info,
    KeyRound,
    Sparkles,
} from "lucide-react";
import {
    BarChart,
    Bar,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    Legend,
    ResponsiveContainer,
    RadarChart,
    PolarGrid,
    PolarAngleAxis,
    PolarRadiusAxis,
    Radar,
} from "recharts";
import {
    ExperimentStats,
    ExperimentScenarioStats,
    fetchExperimentLookup,
    fetchExperimentStats,
} from "@/lib/api";

type SortField =
    | "component"
    | "category"
    | "chain_length"
    | "pov_rate"
    | "exp_rate"
    | "aifw_bypass_rate";

type SortDirection = "asc" | "desc" | null;

const POV_EXP_ATTEMPTS = [1, 2, 3, 4, 5];
const AIFW_BYPASS_ATTEMPTS = [1, 2, 3];

export default function ExperimentPage() {
    const [data, setData] = useState<ExperimentStats | null>(null);
    const [loading, setLoading] = useState(true);
    const [tableSearch, setTableSearch] = useState("");
    const [queryKey, setQueryKey] = useState("");
    const [lookupLoading, setLookupLoading] = useState(false);
    const [lookupResult, setLookupResult] = useState<ExperimentScenarioStats | null>(null);
    const [lookupSuggestions, setLookupSuggestions] = useState<string[]>([]);
    const [lookupMessage, setLookupMessage] = useState("");
    const [sortField, setSortField] = useState<SortField | null>(null);
    const [sortDirection, setSortDirection] = useState<SortDirection>(null);

    useEffect(() => {
        fetchExperimentStats()
            .then((stats) => {
                setData(stats);
                const firstScenario = stats.by_scenario?.[0];
                if (firstScenario) {
                    setQueryKey(firstScenario.query_key);
                    setLookupResult(firstScenario);
                }
            })
            .catch(console.error)
            .finally(() => setLoading(false));
    }, []);

    const categoryChartData = useMemo(() => {
        if (!data) return [];
        return Object.entries(data.by_category).map(([cat, value]) => ({
            category: cat,
            POV: Math.round(value.pov_rate * 100),
            EXP: Math.round(value.exp_rate * 100),
            Bypass: Math.round(value.aifw_bypass_rate * 100),
        }));
    }, [data]);

    const radarData = useMemo(() => {
        if (!data) return [];
        const labelMap: Record<string, string> = {
            RCE: "RCE 利用",
            FILEREAD: "文件读取",
            SQLI: "SQL 注入",
        };
        return Object.entries(data.by_category).map(([cat, value]) => ({
            dimension: labelMap[cat] || cat,
            POV: Math.round(value.pov_rate * 100),
            EXP: Math.round(value.exp_rate * 100),
            Bypass: Math.round(value.aifw_bypass_rate * 100),
        }));
    }, [data]);

    const quickQueryKeys = useMemo(() => {
        if (!data) return [];
        return data.by_scenario.slice(0, 6).map((scenario) => scenario.query_key);
    }, [data]);

    const filteredScenarios = useMemo(() => {
        if (!data) return [];
        let list = data.by_scenario;
        if (tableSearch.trim()) {
            const query = tableSearch.toLowerCase();
            list = list.filter(
                (scenario) =>
                    scenario.component.toLowerCase().includes(query) ||
                    scenario.version.toLowerCase().includes(query) ||
                    scenario.scenario_id.toLowerCase().includes(query) ||
                    scenario.query_key.toLowerCase().includes(query)
            );
        }

        if (!sortField || !sortDirection) {
            return list;
        }

        return [...list].sort((a, b) => {
            const valueA = a[sortField];
            const valueB = b[sortField];
            if (typeof valueA === "string" && typeof valueB === "string") {
                return sortDirection === "asc"
                    ? valueA.localeCompare(valueB)
                    : valueB.localeCompare(valueA);
            }
            return sortDirection === "asc"
                ? Number(valueA ?? 0) - Number(valueB ?? 0)
                : Number(valueB ?? 0) - Number(valueA ?? 0);
        });
    }, [data, tableSearch, sortField, sortDirection]);

    const handleSort = (field: SortField) => {
        if (sortField !== field) {
            setSortField(field);
            setSortDirection("asc");
            return;
        }

        if (sortDirection === "asc") {
            setSortDirection("desc");
            return;
        }

        if (sortDirection === "desc") {
            setSortField(null);
            setSortDirection(null);
            return;
        }

        setSortDirection("asc");
    };

    const handleLookup = async (event: FormEvent<HTMLFormElement>) => {
        event.preventDefault();
        if (!queryKey.trim()) {
            setLookupMessage("请输入组件名@版本号后再查询");
            setLookupSuggestions([]);
            setLookupResult(null);
            return;
        }

        setLookupLoading(true);
        try {
            const res = await fetchExperimentLookup(queryKey.trim());
            setLookupSuggestions(res.suggestions);
            if (res.found && res.data) {
                setLookupResult(res.data);
                setLookupMessage(`已匹配到 ${res.query_key}`);
            } else {
                setLookupResult(null);
                setLookupMessage("未命中精确主键，可尝试下方推荐项");
            }
        } catch (error) {
            console.error(error);
            setLookupMessage("主键查询失败");
            setLookupSuggestions([]);
            setLookupResult(null);
        } finally {
            setLookupLoading(false);
        }
    };

    const SortIcon = ({ field }: { field: SortField }) => {
        if (sortField !== field || !sortDirection) {
            return <ArrowUpDown className="w-3 h-3 opacity-40" />;
        }
        return sortDirection === "asc" ? (
            <ChevronUp className="w-3 h-3 text-blue-500" />
        ) : (
            <ChevronDown className="w-3 h-3 text-blue-500" />
        );
    };

    if (loading) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="animate-pulse text-slate-500 dark:text-slate-400">
                    加载实验数据...
                </div>
            </div>
        );
    }

    if (!data) {
        return (
            <div className="min-h-screen flex items-center justify-center">
                <div className="text-red-500">无法加载实验数据</div>
            </div>
        );
    }

    return (
        <div className="container mx-auto px-4 py-8 space-y-8">
            <div className="border-b border-slate-200 dark:border-slate-800 pb-6">
                <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white mb-2 flex items-center gap-3">
                    <span className="inline-flex items-center justify-center w-11 h-11 rounded-2xl bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300">
                        <FlaskConical className="w-6 h-6" />
                    </span>
                    Long-Range Attack Chain Quantitative Experiment Dashboard
                </h1>
                <p className="text-slate-500 dark:text-slate-400">
                    以组件名+版本号作为查询主键，统一展示 POV 构建准确率、EXP 构建准确率与 AIFW 绕过成功率
                </p>
            </div>

            <div className="rounded-2xl border border-sky-200/70 bg-sky-50/80 dark:border-sky-900/50 dark:bg-sky-950/30 p-5">
                <SectionHeading
                    title="指标说明"
                    icon={<Info className="w-4.5 h-4.5" />}
                    className="mb-3 text-sky-900 dark:text-sky-100"
                    iconClassName="bg-sky-100 text-sky-600 dark:bg-sky-900/40 dark:text-sky-300"
                />
                <div className="space-y-2 text-sm text-slate-700 dark:text-slate-300">
                    <p>
                        注1：`POV 构建准确率` 侧重单漏洞场景下最小触发样例的自动构造能力。每个样本独立构建 5 次，出现明确回显或可审计日志即判定成功。
                    </p>
                    <p>
                        注2：`EXP 构建准确率` 侧重长距离攻击链端到端打通能力。每个样本独立构建 5 次，最终达成命令执行、提权、敏感数据读取或持久化等预设目标即判定成功。
                    </p>
                    <p>
                        注3：`AIFW 绕过成功率` 衡量防护开启条件下攻击链继续推进的能力。本页保持每个样本 3 次 AIFW 绕过尝试，成功穿透检测或拦截链路即记为成功。
                    </p>
                </div>
            </div>

            <div className="grid grid-cols-2 xl:grid-cols-5 gap-4">
                <SummaryCard
                    label="POV 构建准确率"
                    value={`${(data.pov_overall.rate * 100).toFixed(1)}%`}
                    sub={`${data.pov_overall.success} / ${data.pov_overall.total}`}
                    color="blue"
                />
                <SummaryCard
                    label="EXP 构建准确率"
                    value={`${(data.exp_overall.rate * 100).toFixed(1)}%`}
                    sub={`${data.exp_overall.success} / ${data.exp_overall.total}`}
                    color="amber"
                />
                <SummaryCard
                    label="AIFW 绕过成功率"
                    value={`${(data.aifw_bypass_overall.rate * 100).toFixed(1)}%`}
                    sub={`${data.aifw_bypass_overall.success} / ${data.aifw_bypass_overall.total}`}
                    color="emerald"
                />
                <SummaryCard
                    label="测试场景数"
                    value={String(data.scenario_count)}
                    sub="内置靶场样本"
                    color="slate"
                />
                <SummaryCard
                    label="总尝试次数"
                    value={String(data.total_runs)}
                    sub="POV + EXP + 绕过"
                    color="purple"
                />
            </div>

            <div className="grid grid-cols-1 xl:grid-cols-[1.1fr_1.4fr] gap-6 items-stretch">
                <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm relative overflow-hidden h-full flex flex-col">
                    <div className="absolute inset-x-0 top-0 h-24 bg-gradient-to-r from-indigo-500/10 via-sky-500/5 to-transparent pointer-events-none" />
                    <SectionHeading title="主键检索" icon={<Crosshair className="w-4.5 h-4.5" />} className="mb-2" />
                    <p className="text-sm text-slate-500 dark:text-slate-400 mb-4">
                        输入格式建议为 `组件名@版本号`，例如 `Langflow@1.2.0`
                    </p>
                    <div className="grid grid-cols-1 md:grid-cols-[1.2fr_0.8fr] gap-4 flex-1">
                        <div className="space-y-4 flex flex-col">
                            <form className="space-y-3" onSubmit={handleLookup}>
                                <div className="relative">
                                    <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                                    <input
                                        list="experiment-query-keys"
                                        type="text"
                                        value={queryKey}
                                        onChange={(event) => setQueryKey(event.target.value)}
                                        placeholder="Apache Tomcat@9.0.86"
                                        className="w-full pl-9 pr-3 py-3 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                                    />
                                    <datalist id="experiment-query-keys">
                                        {data.by_scenario.map((scenario) => (
                                            <option key={scenario.query_key} value={scenario.query_key} />
                                        ))}
                                    </datalist>
                                </div>
                                <button
                                    type="submit"
                                    disabled={lookupLoading}
                                    className="w-full inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-4 py-3 text-sm font-medium text-white hover:bg-indigo-500 disabled:cursor-not-allowed disabled:opacity-60 transition-colors"
                                >
                                    <Search className="w-4 h-4" />
                                    {lookupLoading ? "匹配中..." : "按主键匹配场景"}
                                </button>
                            </form>

                            <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50/80 dark:bg-slate-950/40 p-4 flex-1">
                                <div className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-200">
                                    <KeyRound className="w-4 h-4 text-indigo-500" />
                                    匹配规则
                                </div>
                                <div className="mt-3 space-y-2 text-xs text-slate-500 dark:text-slate-400">
                                    <p>支持 `组件名@版本号`、`组件名/版本号`、`组件名 版本号` 三种输入形式。</p>
                                    <p>建议优先使用 `@` 作为分隔符，便于在答辩展示时直观说明主键规则。</p>
                                    <p>未命中精确结果时，系统会根据组件名、版本号和 CVE 给出推荐项。</p>
                                </div>
                            </div>
                        </div>

                        <div className="rounded-xl border border-slate-200 dark:border-slate-800 bg-gradient-to-br from-indigo-50 via-white to-sky-50 dark:from-slate-900 dark:via-slate-900 dark:to-slate-950 p-4 flex flex-col">
                            <div className="flex items-center gap-2 text-sm font-medium text-slate-700 dark:text-slate-200">
                                <Sparkles className="w-4 h-4 text-indigo-500" />
                                快速示例
                            </div>
                            <div className="mt-3 flex flex-wrap gap-2">
                                {quickQueryKeys.map((item) => (
                                    <button
                                        key={item}
                                        type="button"
                                        onClick={() => setQueryKey(item)}
                                        className="px-3 py-1.5 rounded-full text-xs font-medium bg-white text-slate-700 hover:bg-slate-100 dark:bg-slate-800 dark:text-slate-200 dark:hover:bg-slate-700 border border-slate-200 dark:border-slate-700 transition-colors"
                                    >
                                        {item}
                                    </button>
                                ))}
                            </div>

                            <div className="mt-auto pt-4">
                                <div className="rounded-lg border border-slate-200/80 dark:border-slate-800 bg-white/80 dark:bg-slate-950/70 p-3">
                                    <div className="text-[11px] uppercase tracking-wide text-slate-400 dark:text-slate-500">
                                        Query Pattern
                                    </div>
                                    <div className="mt-1 text-sm font-medium text-slate-700 dark:text-slate-200">
                                        component@version
                                    </div>
                                    <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
                                        示例主键可一键填充输入框，便于答辩演示快速切换样本。
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div className="mt-4 pt-4 border-t border-slate-100 dark:border-slate-800 space-y-3">
                        <div className="min-h-5 text-sm">
                            {lookupMessage ? (
                                <p className="text-slate-500 dark:text-slate-400">{lookupMessage}</p>
                            ) : (
                                <p className="text-slate-400 dark:text-slate-500">可通过主键快速命中对应组件版本的实验画像。</p>
                            )}
                        </div>

                        {lookupSuggestions.length > 0 && (
                            <div className="flex flex-wrap gap-2">
                                {lookupSuggestions.map((item) => (
                                    <button
                                        key={item}
                                        type="button"
                                        onClick={() => setQueryKey(item)}
                                        className="px-3 py-1.5 rounded-full text-xs font-medium bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700 transition-colors"
                                    >
                                        {item}
                                    </button>
                                ))}
                            </div>
                        )}
                    </div>
                </div>

                <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm h-full flex flex-col">
                    <SectionHeading title="场景画像" icon={<Binary className="w-4.5 h-4.5" />} className="mb-4" />
                    {lookupResult ? (
                        <div className="space-y-4 h-full flex flex-col">
                            <div className="flex flex-col lg:flex-row lg:items-start lg:justify-between gap-3">
                                <div>
                                    <div className="text-xl font-semibold text-slate-900 dark:text-white">
                                        {lookupResult.component}
                                        <span className="text-slate-400 dark:text-slate-500 text-base font-normal ml-2">
                                            {lookupResult.version}
                                        </span>
                                    </div>
                                    <div className="mt-1 text-xs font-mono text-slate-500 dark:text-slate-400">
                                        {lookupResult.query_key}
                                    </div>
                                </div>
                                <div className="flex flex-wrap gap-2">
                                    <CategoryBadge category={lookupResult.category} />
                                    <InfoChip label="CVE" value={lookupResult.scenario_id} mono />
                                    <InfoChip label="链路长度" value={`${lookupResult.chain_length ?? "-"} 跳`} />
                                </div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                                <LookupMetric
                                    label="POV"
                                    rate={lookupResult.pov_rate}
                                    detail={`${lookupResult.pov_success}/${lookupResult.pov_total}`}
                                    color="blue"
                                />
                                <LookupMetric
                                    label="EXP"
                                    rate={lookupResult.exp_rate}
                                    detail={`${lookupResult.exp_success}/${lookupResult.exp_total}`}
                                    color="amber"
                                />
                                <LookupMetric
                                    label="AIFW 绕过"
                                    rate={lookupResult.aifw_bypass_rate}
                                    detail={`${lookupResult.aifw_bypass_success}/${lookupResult.aifw_bypass_total}`}
                                    color="emerald"
                                />
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm flex-1">
                                <InfoBlock title="攻击目标" content={lookupResult.attack_goal || "未配置"} />
                                <InfoBlock
                                    title="绕过策略"
                                    content={lookupResult.aifw_bypass_strategy || "未配置"}
                                />
                            </div>

                            <div className="mt-auto pt-4 border-t border-slate-100 dark:border-slate-800">
                                <div className="text-[11px] uppercase tracking-wide text-slate-400 dark:text-slate-500 mb-3">
                                    Builders
                                </div>
                                <div className="flex flex-wrap gap-2">
                                    <BuilderTag text={lookupResult.pov_builder || "AI Payload Generator"} />
                                    <BuilderTag text={lookupResult.exp_builder || "Multi-Agent"} />
                                </div>
                            </div>
                        </div>
                    ) : (
                        <div className="h-full min-h-40 flex-1 flex items-center justify-center text-sm text-slate-400 dark:text-slate-500">
                            暂无匹配结果
                        </div>
                    )}
                </div>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
                    <SectionHeading title="按漏洞类别对比三类指标" icon={<BarChart3 className="w-4.5 h-4.5" />} className="mb-4" />
                    <ResponsiveContainer width="100%" height={320}>
                        <BarChart data={categoryChartData} barGap={4} barCategoryGap="20%">
                            <CartesianGrid strokeDasharray="3 3" stroke="#334155" opacity={0.2} />
                            <XAxis
                                dataKey="category"
                                tick={{ fill: "#94a3b8", fontSize: 13 }}
                                axisLine={{ stroke: "#475569" }}
                            />
                            <YAxis
                                domain={[0, 100]}
                                tick={{ fill: "#94a3b8", fontSize: 12 }}
                                axisLine={{ stroke: "#475569" }}
                                tickFormatter={(value) => `${value}%`}
                            />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: "#1e293b",
                                    border: "1px solid #334155",
                                    borderRadius: "8px",
                                    color: "#e2e8f0",
                                }}
                                formatter={(value) => [`${value ?? 0}%`, ""]}
                            />
                            <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 13 }} />
                            <Bar dataKey="POV" name="POV 准确率" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                            <Bar dataKey="EXP" name="EXP 准确率" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                            <Bar dataKey="Bypass" name="AIFW 绕过率" fill="#10b981" radius={[4, 4, 0, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
                    <SectionHeading title="多维能力评估" icon={<RadarIcon className="w-4.5 h-4.5" />} className="mb-4" />
                    <ResponsiveContainer width="100%" height={320}>
                        <RadarChart data={radarData} cx="50%" cy="50%" outerRadius="70%">
                            <PolarGrid stroke="#475569" opacity={0.3} />
                            <PolarAngleAxis
                                dataKey="dimension"
                                tick={{ fill: "#94a3b8", fontSize: 13 }}
                            />
                            <PolarRadiusAxis
                                domain={[0, 100]}
                                tick={{ fill: "#64748b", fontSize: 11 }}
                                tickFormatter={(value) => `${value}%`}
                            />
                            <Radar
                                name="POV 准确率"
                                dataKey="POV"
                                stroke="#3b82f6"
                                fill="#3b82f6"
                                fillOpacity={0.25}
                                strokeWidth={2}
                            />
                            <Radar
                                name="EXP 准确率"
                                dataKey="EXP"
                                stroke="#f59e0b"
                                fill="#f59e0b"
                                fillOpacity={0.2}
                                strokeWidth={2}
                            />
                            <Radar
                                name="AIFW 绕过率"
                                dataKey="Bypass"
                                stroke="#10b981"
                                fill="#10b981"
                                fillOpacity={0.15}
                                strokeWidth={2}
                            />
                            <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 13 }} />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: "#1e293b",
                                    border: "1px solid #334155",
                                    borderRadius: "8px",
                                    color: "#e2e8f0",
                                }}
                                formatter={(value) => [`${value ?? 0}%`, ""]}
                            />
                        </RadarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
                <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4 mb-5">
                    <SectionHeading title="逐场景实验结果" icon={<Table2 className="w-4.5 h-4.5" />} />
                    <div className="relative w-full lg:w-80">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                        <input
                            type="text"
                            placeholder="按组件 / 版本 / CVE / 主键过滤..."
                            value={tableSearch}
                            onChange={(event) => setTableSearch(event.target.value)}
                            className="w-full pl-9 pr-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        />
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-sm min-w-[1560px]">
                        <thead>
                            <tr className="border-b border-slate-200 dark:border-slate-700">
                                <SortableHeader
                                    label="组件 + 版本"
                                    field="component"
                                    onSort={handleSort}
                                    sortIcon={<SortIcon field="component" />}
                                />
                                <th className="px-3 py-3 text-left font-medium text-slate-500 dark:text-slate-400">
                                    CVE
                                </th>
                                <SortableHeader
                                    label="类别"
                                    field="category"
                                    onSort={handleSort}
                                    sortIcon={<SortIcon field="category" />}
                                />
                                <SortableHeader
                                    label="链路长度"
                                    field="chain_length"
                                    onSort={handleSort}
                                    sortIcon={<SortIcon field="chain_length" />}
                                    className="text-center"
                                />
                                <th className="px-2 py-3 text-center font-medium text-slate-500 dark:text-slate-400" colSpan={5}>
                                    POV 尝试
                                </th>
                                <th className="px-2 py-3 text-center font-medium text-slate-500 dark:text-slate-400 border-l border-slate-200 dark:border-slate-700" colSpan={5}>
                                    EXP 尝试
                                </th>
                                <th className="px-2 py-3 text-center font-medium text-slate-500 dark:text-slate-400 border-l border-slate-200 dark:border-slate-700" colSpan={3}>
                                    AIFW 绕过尝试
                                </th>
                                <SortableHeader
                                    label="POV率"
                                    field="pov_rate"
                                    onSort={handleSort}
                                    sortIcon={<SortIcon field="pov_rate" />}
                                    className="text-center border-l border-slate-200 dark:border-slate-700 w-[68px] whitespace-nowrap"
                                />
                                <SortableHeader
                                    label="EXP率"
                                    field="exp_rate"
                                    onSort={handleSort}
                                    sortIcon={<SortIcon field="exp_rate" />}
                                    className="text-center w-[68px] whitespace-nowrap"
                                />
                                <SortableHeader
                                    label="AIFW绕过率"
                                    field="aifw_bypass_rate"
                                    onSort={handleSort}
                                    sortIcon={<SortIcon field="aifw_bypass_rate" />}
                                    className="text-center w-[92px] whitespace-nowrap"
                                />
                            </tr>
                            <tr className="border-b border-slate-100 dark:border-slate-800 text-[11px] text-slate-400 dark:text-slate-500">
                                <th />
                                <th />
                                <th />
                                <th />
                                {POV_EXP_ATTEMPTS.map((index) => (
                                    <th key={`p-${index}`} className="px-2 py-1 text-center font-normal">
                                        #{index}
                                    </th>
                                ))}
                                {POV_EXP_ATTEMPTS.map((index) => (
                                    <th
                                        key={`e-${index}`}
                                        className={`px-2 py-1 text-center font-normal ${index === 1 ? "border-l border-slate-200 dark:border-slate-700" : ""}`}
                                    >
                                        #{index}
                                    </th>
                                ))}
                                {AIFW_BYPASS_ATTEMPTS.map((index) => (
                                    <th
                                        key={`b-${index}`}
                                        className={`px-2 py-1 text-center font-normal ${index === 1 ? "border-l border-slate-200 dark:border-slate-700" : ""}`}
                                    >
                                        #{index}
                                    </th>
                                ))}
                                <th className="border-l border-slate-200 dark:border-slate-700" />
                                <th />
                                <th />
                            </tr>
                        </thead>
                        <tbody>
                            {filteredScenarios.map((scenario) => (
                                <tr
                                    key={scenario.query_key}
                                    className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                                >
                                    <td className="px-3 py-3 font-medium text-slate-800 dark:text-slate-200">
                                        <div className="whitespace-nowrap">
                                            {scenario.component}
                                            <span className="text-xs text-slate-400 dark:text-slate-500 font-normal ml-1">
                                                / {scenario.version}
                                            </span>
                                        </div>
                                        <div className="text-[11px] text-slate-400 dark:text-slate-500 font-mono mt-1">
                                            {scenario.query_key}
                                        </div>
                                    </td>
                                    <td className="px-3 py-3 text-slate-500 dark:text-slate-400 font-mono text-xs whitespace-nowrap">
                                        {scenario.scenario_id}
                                    </td>
                                    <td className="px-3 py-3">
                                        <CategoryBadge category={scenario.category} />
                                    </td>
                                    <td className="px-3 py-3 text-center text-slate-500 dark:text-slate-400">
                                        {scenario.chain_length ?? "-"}
                                    </td>
                                    {POV_EXP_ATTEMPTS.map((attempt) => (
                                        <td key={`pov-${scenario.query_key}-${attempt}`} className="px-2 py-3 text-center">
                                            <ResultCell value={scenario.pov_results[attempt - 1]} />
                                        </td>
                                    ))}
                                    {POV_EXP_ATTEMPTS.map((attempt) => (
                                        <td
                                            key={`exp-${scenario.query_key}-${attempt}`}
                                            className={`px-2 py-3 text-center ${attempt === 1 ? "border-l border-slate-200 dark:border-slate-700" : ""}`}
                                        >
                                            <ResultCell value={scenario.exp_results[attempt - 1]} />
                                        </td>
                                    ))}
                                    {AIFW_BYPASS_ATTEMPTS.map((attempt) => (
                                        <td
                                            key={`bypass-${scenario.query_key}-${attempt}`}
                                            className={`px-2 py-3 text-center ${attempt === 1 ? "border-l border-slate-200 dark:border-slate-700" : ""}`}
                                        >
                                            <ResultCell value={scenario.aifw_bypass_results[attempt - 1]} />
                                        </td>
                                    ))}
                                    <td className="px-2 py-3 text-center border-l border-slate-200 dark:border-slate-700 w-[68px] whitespace-nowrap">
                                        <RateLabel rate={scenario.pov_rate} />
                                    </td>
                                    <td className="px-2 py-3 text-center w-[68px] whitespace-nowrap">
                                        <RateLabel rate={scenario.exp_rate} />
                                    </td>
                                    <td className="px-2 py-3 text-center w-[92px] whitespace-nowrap">
                                        <RateLabel rate={scenario.aifw_bypass_rate} tone="emerald" />
                                    </td>
                                </tr>
                            ))}
                            {filteredScenarios.length === 0 && (
                                <tr>
                                    <td colSpan={20} className="py-8 text-center text-slate-400 dark:text-slate-500">
                                        未找到匹配的场景
                                    </td>
                                </tr>
                            )}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    );
}

function SummaryCard({
    label,
    value,
    sub,
    color,
}: {
    label: string;
    value: string;
    sub: string;
    color: "blue" | "amber" | "emerald" | "purple" | "slate";
}) {
    const ring: Record<string, string> = {
        blue: "ring-blue-500/20",
        amber: "ring-amber-500/20",
        emerald: "ring-emerald-500/20",
        purple: "ring-purple-500/20",
        slate: "ring-slate-500/20",
    };
    const accent: Record<string, string> = {
        blue: "text-blue-600 dark:text-blue-400",
        amber: "text-amber-600 dark:text-amber-400",
        emerald: "text-emerald-600 dark:text-emerald-400",
        purple: "text-purple-600 dark:text-purple-400",
        slate: "text-slate-700 dark:text-slate-200",
    };

    return (
        <div
            className={`bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-5 shadow-sm ring-1 ${ring[color]}`}
        >
            <div className="text-xs font-medium text-slate-500 dark:text-slate-400 mb-1 uppercase tracking-wide">
                {label}
            </div>
            <div className={`text-3xl font-bold ${accent[color]}`}>{value}</div>
            <div className="text-sm text-slate-400 dark:text-slate-500 mt-1">{sub}</div>
        </div>
    );
}

function SectionHeading({
    title,
    icon,
    className = "",
    iconClassName = "",
}: {
    title: string;
    icon: React.ReactNode;
    className?: string;
    iconClassName?: string;
}) {
    return (
        <div className={`flex items-center gap-3 text-slate-900 dark:text-slate-100 ${className}`}>
            <span
                className={`inline-flex items-center justify-center w-9 h-9 rounded-xl bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300 ${iconClassName}`}
            >
                {icon}
            </span>
            <h2 className="text-lg font-semibold tracking-tight">{title}</h2>
        </div>
    );
}

function SortableHeader({
    label,
    field,
    onSort,
    sortIcon,
    className = "",
}: {
    label: string;
    field: SortField;
    onSort: (field: SortField) => void;
    sortIcon: React.ReactNode;
    className?: string;
}) {
    return (
        <th
            className={`px-3 py-3 font-medium text-slate-500 dark:text-slate-400 cursor-pointer select-none hover:text-slate-700 dark:hover:text-slate-200 transition-colors text-left ${className}`}
            onClick={() => onSort(field)}
        >
            <span className="inline-flex items-center gap-1">
                {label}
                {sortIcon}
            </span>
        </th>
    );
}

function ResultDot({ success }: { success: boolean }) {
    return success ? (
        <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-emerald-100 dark:bg-emerald-900/40">
            <CheckCircle2 className="w-4 h-4 text-emerald-600 dark:text-emerald-400" />
        </span>
    ) : (
        <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-red-100 dark:bg-red-900/40">
            <XCircle className="w-4 h-4 text-red-500 dark:text-red-400" />
        </span>
    );
}

function ResultCell({ value }: { value?: boolean }) {
    if (typeof value !== "boolean") {
        return (
            <span className="inline-flex items-center justify-center w-6 h-6 rounded-full bg-slate-100 text-slate-400 dark:bg-slate-800 dark:text-slate-500">
                -
            </span>
        );
    }

    return <ResultDot success={value} />;
}

function RateLabel({
    rate,
    tone = "default",
}: {
    rate: number;
    tone?: "default" | "emerald";
}) {
    const pct = Math.round(rate * 100);
    let cls =
        pct >= 100
            ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/30"
            : pct >= 67
              ? "text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30"
              : pct >= 34
                ? "text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/30"
                : "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/30";

    if (tone === "emerald" && pct >= 67) {
        cls = "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/30";
    }

    return <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>{pct}%</span>;
}

function CategoryBadge({ category }: { category: string }) {
    const styles: Record<string, string> = {
        RCE: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
        FILEREAD: "bg-sky-100 text-sky-700 dark:bg-sky-900/30 dark:text-sky-400",
        SQLI: "bg-violet-100 text-violet-700 dark:bg-violet-900/30 dark:text-violet-400",
    };

    return (
        <span
            className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${styles[category] || "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300"}`}
        >
            {category}
        </span>
    );
}

function LookupMetric({
    label,
    rate,
    detail,
    color,
}: {
    label: string;
    rate: number;
    detail: string;
    color: "blue" | "amber" | "emerald";
}) {
    const palette: Record<string, string> = {
        blue: "text-blue-600 bg-blue-50 dark:text-blue-400 dark:bg-blue-900/20",
        amber: "text-amber-600 bg-amber-50 dark:text-amber-400 dark:bg-amber-900/20",
        emerald: "text-emerald-600 bg-emerald-50 dark:text-emerald-400 dark:bg-emerald-900/20",
    };

    return (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 p-4">
            <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">{label}</div>
            <div className={`inline-flex mt-2 px-3 py-1 rounded-full text-lg font-semibold ${palette[color]}`}>
                {(rate * 100).toFixed(1)}%
            </div>
            <div className="mt-2 text-sm text-slate-500 dark:text-slate-400">{detail}</div>
        </div>
    );
}

function InfoBlock({ title, content }: { title: string; content: string }) {
    return (
        <div className="rounded-xl border border-slate-200 dark:border-slate-800 p-4">
            <div className="text-xs uppercase tracking-wide text-slate-500 dark:text-slate-400">{title}</div>
            <div className="mt-2 text-sm text-slate-700 dark:text-slate-200">{content}</div>
        </div>
    );
}

function InfoChip({
    label,
    value,
    mono = false,
}: {
    label: string;
    value: string;
    mono?: boolean;
}) {
    return (
        <span className="inline-flex items-center gap-1 rounded-full bg-slate-100 dark:bg-slate-800 px-3 py-1 text-xs text-slate-600 dark:text-slate-300">
            <span className="text-slate-400 dark:text-slate-500">{label}</span>
            <span className={mono ? "font-mono" : ""}>{value}</span>
        </span>
    );
}

function BuilderTag({ text }: { text: string }) {
    return (
        <span className="inline-flex items-center gap-2 rounded-full border border-slate-200 dark:border-slate-700 px-3 py-1.5 text-xs text-slate-600 dark:text-slate-300">
            <ShieldOff className="w-3.5 h-3.5 text-slate-400" />
            {text}
        </span>
    );
}
