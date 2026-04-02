"use client";

import React, { useState, useEffect, useMemo } from "react";
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
import { fetchExperimentStats } from "@/lib/api";

interface ScenarioStats {
    scenario_id: string;
    component: string;
    version: string;
    category: string;
    pov_results: boolean[];
    exp_results: boolean[];
    pov_success: number;
    pov_total: number;
    pov_rate: number;
    exp_success: number;
    exp_total: number;
    exp_rate: number;
}

interface CategoryStats {
    pov_success: number;
    pov_total: number;
    pov_rate: number;
    exp_success: number;
    exp_total: number;
    exp_rate: number;
}

interface ExperimentData {
    pov_overall: { success: number; total: number; rate: number };
    exp_overall: { success: number; total: number; rate: number };
    scenario_count: number;
    total_runs: number;
    by_category: Record<string, CategoryStats>;
    by_scenario: ScenarioStats[];
}

type SortField = "component" | "category" | "pov_rate" | "exp_rate";

export default function ExperimentPage() {
    const [data, setData] = useState<ExperimentData | null>(null);
    const [loading, setLoading] = useState(true);
    const [search, setSearch] = useState("");
    const [sortField, setSortField] = useState<SortField>("component");
    const [sortAsc, setSortAsc] = useState(true);

    useEffect(() => {
        fetchExperimentStats()
            .then((d) => setData(d))
            .catch(console.error)
            .finally(() => setLoading(false));
    }, []);

    const categoryChartData = useMemo(() => {
        if (!data) return [];
        return Object.entries(data.by_category).map(([cat, v]) => ({
            category: cat,
            POV: Math.round(v.pov_rate * 100),
            EXP: Math.round(v.exp_rate * 100),
        }));
    }, [data]);

    const radarData = useMemo(() => {
        if (!data) return [];
        const labelMap: Record<string, string> = {
            RCE: "RCE 利用",
            FILEREAD: "文件读取",
            SQLI: "SQL 注入",
        };
        return Object.entries(data.by_category).map(([cat, v]) => ({
            dimension: labelMap[cat] || cat,
            POV: Math.round(v.pov_rate * 100),
            EXP: Math.round(v.exp_rate * 100),
        }));
    }, [data]);

    const filteredScenarios = useMemo(() => {
        if (!data) return [];
        let list = data.by_scenario;
        if (search.trim()) {
            const q = search.toLowerCase();
            list = list.filter(
                (s) =>
                    s.component.toLowerCase().includes(q) ||
                    s.version.toLowerCase().includes(q) ||
                    s.scenario_id.toLowerCase().includes(q)
            );
        }
        list = [...list].sort((a, b) => {
            const va = a[sortField];
            const vb = b[sortField];
            if (typeof va === "string" && typeof vb === "string") {
                return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
            }
            return sortAsc ? (va as number) - (vb as number) : (vb as number) - (va as number);
        });
        return list;
    }, [data, search, sortField, sortAsc]);

    const handleSort = (field: SortField) => {
        if (sortField === field) {
            setSortAsc(!sortAsc);
        } else {
            setSortField(field);
            setSortAsc(true);
        }
    };

    const SortIcon = ({ field }: { field: SortField }) => {
        if (sortField !== field) return <ArrowUpDown className="w-3 h-3 opacity-40" />;
        return sortAsc ? (
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
            {/* Header */}
            <div className="border-b border-slate-200 dark:border-slate-800 pb-6">
                <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-3">
                    <FlaskConical className="w-8 h-8 text-indigo-500" />
                    量化实验结果
                </h1>
                <p className="text-slate-500 dark:text-slate-400">
                    POV 构建准确率与 EXP 构建准确率对比分析，以组件名+版本号为查询主键
                </p>
            </div>

            {/* ── Row 1: Summary Cards ── */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
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
                    label="测试场景数"
                    value={String(data.scenario_count)}
                    sub="漏洞场景"
                    color="emerald"
                />
                <SummaryCard
                    label="总运行次数"
                    value={String(data.total_runs)}
                    sub="POV + EXP"
                    color="purple"
                />
            </div>

            {/* ── Row 2: Charts ── */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Grouped Bar Chart */}
                <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
                    <h2 className="text-lg font-semibold mb-4 flex items-center gap-2 text-slate-800 dark:text-slate-200">
                        <BarChart3 className="w-5 h-5 text-indigo-500" />
                        按漏洞类别对比准确率
                    </h2>
                    <ResponsiveContainer width="100%" height={320}>
                        <BarChart data={categoryChartData} barGap={4} barCategoryGap="25%">
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
                                tickFormatter={(v) => `${v}%`}
                            />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: "#1e293b",
                                    border: "1px solid #334155",
                                    borderRadius: "8px",
                                    color: "#e2e8f0",
                                }}
                                formatter={(value: number) => [`${value}%`, undefined]}
                            />
                            <Legend
                                wrapperStyle={{ color: "#94a3b8", fontSize: 13 }}
                            />
                            <Bar dataKey="POV" name="POV 准确率" fill="#3b82f6" radius={[4, 4, 0, 0]} />
                            <Bar dataKey="EXP" name="EXP 准确率" fill="#f59e0b" radius={[4, 4, 0, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>

                {/* Radar Chart */}
                <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
                    <h2 className="text-lg font-semibold mb-4 flex items-center gap-2 text-slate-800 dark:text-slate-200">
                        <RadarIcon className="w-5 h-5 text-indigo-500" />
                        多维能力评估
                    </h2>
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
                                tickFormatter={(v) => `${v}%`}
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
                            <Legend wrapperStyle={{ color: "#94a3b8", fontSize: 13 }} />
                            <Tooltip
                                contentStyle={{
                                    backgroundColor: "#1e293b",
                                    border: "1px solid #334155",
                                    borderRadius: "8px",
                                    color: "#e2e8f0",
                                }}
                                formatter={(value: number) => [`${value}%`, undefined]}
                            />
                        </RadarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            {/* ── Row 3: Detail Heatmap Table ── */}
            <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
                <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 mb-5">
                    <h2 className="text-lg font-semibold flex items-center gap-2 text-slate-800 dark:text-slate-200">
                        <Table2 className="w-5 h-5 text-indigo-500" />
                        逐场景实验结果
                    </h2>
                    <div className="relative w-full sm:w-72">
                        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-400" />
                        <input
                            type="text"
                            placeholder="按组件名 / 版本号搜索..."
                            value={search}
                            onChange={(e) => setSearch(e.target.value)}
                            className="w-full pl-9 pr-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-900 dark:text-slate-200 focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        />
                    </div>
                </div>

                <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                        <thead>
                            <tr className="border-b border-slate-200 dark:border-slate-700">
                                <SortableHeader label="组件 + 版本" field="component" onSort={handleSort} sortIcon={<SortIcon field="component" />} />
                                <th className="px-3 py-3 text-left font-medium text-slate-500 dark:text-slate-400">CVE</th>
                                <SortableHeader label="类别" field="category" onSort={handleSort} sortIcon={<SortIcon field="category" />} />
                                <th className="px-2 py-3 text-center font-medium text-slate-500 dark:text-slate-400" colSpan={3}>
                                    POV 尝试
                                </th>
                                <th className="px-2 py-3 text-center font-medium text-slate-500 dark:text-slate-400" colSpan={3}>
                                    EXP 尝试
                                </th>
                                <SortableHeader label="POV率" field="pov_rate" onSort={handleSort} sortIcon={<SortIcon field="pov_rate" />} className="text-center" />
                                <SortableHeader label="EXP率" field="exp_rate" onSort={handleSort} sortIcon={<SortIcon field="exp_rate" />} className="text-center" />
                            </tr>
                            <tr className="border-b border-slate-100 dark:border-slate-800 text-[11px] text-slate-400 dark:text-slate-500">
                                <th></th>
                                <th></th>
                                <th></th>
                                {[1, 2, 3].map((n) => (
                                    <th key={`p${n}`} className="px-2 py-1 text-center font-normal">#{n}</th>
                                ))}
                                {[1, 2, 3].map((n) => (
                                    <th key={`e${n}`} className="px-2 py-1 text-center font-normal">#{n}</th>
                                ))}
                                <th></th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody>
                            {filteredScenarios.map((s) => (
                                <tr
                                    key={s.scenario_id}
                                    className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                                >
                                    <td className="px-3 py-3 font-medium text-slate-800 dark:text-slate-200 whitespace-nowrap">
                                        {s.component}{" "}
                                        <span className="text-xs text-slate-400 dark:text-slate-500 font-normal">
                                            / {s.version}
                                        </span>
                                    </td>
                                    <td className="px-3 py-3 text-slate-500 dark:text-slate-400 font-mono text-xs whitespace-nowrap">
                                        {s.scenario_id}
                                    </td>
                                    <td className="px-3 py-3">
                                        <CategoryBadge category={s.category} />
                                    </td>
                                    {s.pov_results.map((ok, i) => (
                                        <td key={`p${i}`} className="px-2 py-3 text-center">
                                            <ResultDot success={ok} />
                                        </td>
                                    ))}
                                    {s.exp_results.map((ok, i) => (
                                        <td key={`e${i}`} className="px-2 py-3 text-center">
                                            <ResultDot success={ok} />
                                        </td>
                                    ))}
                                    <td className="px-3 py-3 text-center">
                                        <RateLabel rate={s.pov_rate} />
                                    </td>
                                    <td className="px-3 py-3 text-center">
                                        <RateLabel rate={s.exp_rate} />
                                    </td>
                                </tr>
                            ))}
                            {filteredScenarios.length === 0 && (
                                <tr>
                                    <td colSpan={11} className="py-8 text-center text-slate-400 dark:text-slate-500">
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

/* ── Sub-components ── */

function SummaryCard({
    label,
    value,
    sub,
    color,
}: {
    label: string;
    value: string;
    sub: string;
    color: "blue" | "amber" | "emerald" | "purple";
}) {
    const ring: Record<string, string> = {
        blue: "ring-blue-500/20",
        amber: "ring-amber-500/20",
        emerald: "ring-emerald-500/20",
        purple: "ring-purple-500/20",
    };
    const accent: Record<string, string> = {
        blue: "text-blue-600 dark:text-blue-400",
        amber: "text-amber-600 dark:text-amber-400",
        emerald: "text-emerald-600 dark:text-emerald-400",
        purple: "text-purple-600 dark:text-purple-400",
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

function SortableHeader({
    label,
    field,
    onSort,
    sortIcon,
    className = "",
}: {
    label: string;
    field: SortField;
    onSort: (f: SortField) => void;
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

function RateLabel({ rate }: { rate: number }) {
    const pct = Math.round(rate * 100);
    const cls =
        pct >= 100
            ? "text-emerald-600 dark:text-emerald-400 bg-emerald-50 dark:bg-emerald-900/30"
            : pct >= 67
              ? "text-blue-600 dark:text-blue-400 bg-blue-50 dark:bg-blue-900/30"
              : pct >= 34
                ? "text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/30"
                : "text-red-600 dark:text-red-400 bg-red-50 dark:bg-red-900/30";

    return (
        <span className={`inline-block px-2 py-0.5 rounded text-xs font-semibold ${cls}`}>
            {pct}%
        </span>
    );
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
