"use client";

import React, { useEffect, useState } from 'react';
import { Workflow, FileCode, Tag, X, Copy, Loader2, Terminal, Play, Edit, Save, Slash } from 'lucide-react';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

interface AttackChainPoc {
    category: string;
    name: string;
    filename: string;
    content: string | null;
}

interface ExecResult {
    stdout: string;
    stderr: string;
    returncode: number;
}

interface VulnInfo {
    app: string;
    cve: string;
    path: string;
    description: string;
}

export default function AttackChainsPage() {
    const [pocs, setPocs] = useState<AttackChainPoc[]>([]);
    const [vulns, setVulns] = useState<VulnInfo[]>([]);
    const [loading, setLoading] = useState(true);
    const [selectedPoc, setSelectedPoc] = useState<AttackChainPoc | null>(null);
    const [loadingContent, setLoadingContent] = useState(false);

    // Editing state
    const [isEditing, setIsEditing] = useState(false);
    const [editedContent, setEditedContent] = useState('');
    const [saving, setSaving] = useState(false);

    // Execution state
    const [activeTab, setActiveTab] = useState<'code' | 'run'>('code');
    const [runArgs, setRunArgs] = useState('');
    const [running, setRunning] = useState(false);
    const [runOutput, setRunOutput] = useState<ExecResult | null>(null);

    const getCategoryHints = (category: string) => {
        const cat = category.toLowerCase();
        if (cat.includes('rce')) {
            return {
                placeholder: 'http://<target_ip>:<port> "touch /tmp/success"',
                tip: 'RCE exploits often have no output (Blind). Use "touch" or DNSLog to verify.'
            };
        }
        if (cat.includes('sqli')) {
            return {
                placeholder: 'http://<target_ip>:<port> "shell.php"',
                tip: 'SQL Injection (Write File). Provide target URL and filename to write.'
            };
        }
        if (cat.includes('fileread')) {
            return {
                placeholder: 'http://<target_ip>:<port> "/etc/passwd"',
                tip: 'Arbitrary File Read. The file content should appear in STDOUT below.'
            };
        }
        return {
            placeholder: 'http://<target_ip>:<port> <args>',
            tip: 'Enter the target URL and arguments required by the script.'
        };
    };

    const getLanguage = (filename: string) => {
        if (!filename) return 'text';
        if (filename.endsWith('.py')) return 'python';
        if (filename.endsWith('.go')) return 'go';
        if (filename.endsWith('.js') || filename.endsWith('.ts') || filename.endsWith('.tsx')) return 'typescript';
        if (filename.endsWith('.sh')) return 'bash';
        if (filename.endsWith('.json')) return 'json';
        if (filename.endsWith('.yaml') || filename.endsWith('.yml')) return 'yaml';
        return 'text';
    };

    useEffect(() => {
        Promise.all([
            fetch('/api/attack-chains').then(res => res.json()),
            fetch('/api/vulns').then(res => res.json()).catch(() => []),
        ])
            .then(([attackChains, vulnList]) => {
                setPocs(attackChains);
                setVulns(Array.isArray(vulnList) ? vulnList : []);
                setLoading(false);
            })
            .catch(err => {
                console.error(err);
                setLoading(false);
            });
    }, []);

    // Auto-fill target args when a POC is selected and environment is running
    useEffect(() => {
        if (!selectedPoc) return;

        const checkEnvStatus = async () => {
            try {
                const matchingVuln = vulns.find(vuln => vuln.cve === selectedPoc.name);
                if (!matchingVuln?.path) {
                    return;
                }

                const res = await fetch(`/api/vulns/status?path=${encodeURIComponent(matchingVuln.path)}`);
                if (!res.ok) {
                    return;
                }

                const status = await res.json();
                if (status.running && status.containers && status.containers.length > 0) {
                    let targetIp = '<target_ip>';
                    let targetPort = '<port>';

                    // Find IP in DMZ subnet (192.168.6.x)
                    for (const c of status.containers) {
                        if (c.ips) {
                            for (const ipStr of c.ips) {
                                const match = ipStr.match(/(\d+\.\d+\.\d+\.\d+)/);
                                if (match) {
                                    const ip = match[1];
                                    if (ip.startsWith('192.168.6.')) {
                                        targetIp = ip;

                                        if (c.ports && c.ports.length > 0) {
                                            for (const pStr of c.ports) {
                                                if (pStr.includes('->')) {
                                                    const parts = pStr.split('->');
                                                    if (parts.length > 1) {
                                                        targetPort = parts[1].trim().split('/')[0];
                                                        break;
                                                    }
                                                }
                                            }
                                        }
                                        break;
                                    }
                                }
                            }
                        }
                        if (targetIp !== '<target_ip>') break;
                    }

                    const hints = getCategoryHints(selectedPoc.category);
                    let filled = hints.placeholder;

                    if (targetIp !== '<target_ip>') {
                        filled = filled.replace(/<target_ip>/g, targetIp);
                    }
                    if (targetPort !== '<port>') {
                        filled = filled.replace(/<port>/g, targetPort);
                    }

                    if (filled !== hints.placeholder) {
                        setRunArgs(filled);
                    }
                }
            } catch (e) {
                console.error("Failed to check env status", e);
            }
        };

        checkEnvStatus();
    }, [selectedPoc, vulns]);

    const [goOS, setGoOS] = useState('linux');
    const [goArch, setGoArch] = useState('amd64');
    const [osSeparator, setOsSeparator] = useState('&&');

    useEffect(() => {
        // Simple client-side OS detection for preview purposes
        const userAgent = window.navigator.userAgent.toLowerCase();
        if (userAgent.includes('win')) {
            setOsSeparator(';');
        } else {
            setOsSeparator('&&');
        }
    }, []);

    const handlePocClick = async (poc: AttackChainPoc) => {
        // Optimistically open modal
        setSelectedPoc(poc);
        setActiveTab('code');       // Reset tab
        setRunArgs('');             // Reset args
        setRunOutput(null);         // Reset output
        setGoOS('linux');           // Reset OS
        setGoArch('amd64');         // Reset Arch

        // If content is already loaded, don't fetch again
        if (poc.content) return;

        setLoadingContent(true);
        try {
            const res = await fetch(`/api/attack-chains/content?category=${poc.category}&name=${poc.name}&filename=${poc.filename}`);
            if (res.ok) {
                const data = await res.json();
                setSelectedPoc(prev => (prev && prev.name === poc.name && prev.filename === poc.filename) ? { ...prev, content: data.content } : prev);

                // Also update the list so we don't fetch again next time
                setPocs(prevPocs => prevPocs.map(p =>
                    (p.name === poc.name && p.filename === poc.filename) ? { ...p, content: data.content } : p
                ));
            }
        } catch (err) {
            console.error("Failed to load content", err);
        } finally {
            setLoadingContent(false);
        }
    };

    const handleEdit = () => {
        if (!selectedPoc || !selectedPoc.content) return;
        setEditedContent(selectedPoc.content);
        setIsEditing(true);
        setActiveTab('code'); // Force switch to code tab
    };

    const handleSave = async () => {
        if (!selectedPoc) return;
        setSaving(true);
        try {
            const res = await fetch('/api/attack-chains/save', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    category: selectedPoc.category,
                    name: selectedPoc.name,
                    filename: selectedPoc.filename,
                    content: editedContent
                })
            });

            if (res.ok) {
                // Update local state
                const newPoc = { ...selectedPoc, content: editedContent };
                setSelectedPoc(newPoc);
                setPocs(prev => prev.map(p =>
                    (p.name === selectedPoc.name && p.filename === selectedPoc.filename) ? newPoc : p
                ));
                setIsEditing(false);
            } else {
                console.error("Failed to save");
                alert("Failed to save content");
            }
        } catch (err) {
            console.error("Save error", err);
            alert("Error saving content");
        } finally {
            setSaving(false);
        }
    };

    const handleCancelEdit = () => {
        setIsEditing(false);
        setEditedContent('');
    };

    const handleRun = async () => {
        if (!selectedPoc) return;
        setRunning(true);
        setRunOutput(null);
        try {
            const payload: any = {
                category: selectedPoc.category,
                name: selectedPoc.name,
                filename: selectedPoc.filename,
                args: runArgs
            };

            if (selectedPoc.filename.endsWith('.go')) {
                payload.go_os = goOS;
                payload.go_arch = goArch;
            }

            const res = await fetch('/api/attack-chains/run', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });
            const data = await res.json();
            setRunOutput(data);
        } catch (err) {
            console.error(err);
            setRunOutput({ stdout: '', stderr: 'Request failed', returncode: -1 });
        } finally {
            setRunning(false);
        }
    }

    // Group by category
    const grouped = pocs.reduce((acc, poc) => {
        if (!acc[poc.category]) acc[poc.category] = [];
        acc[poc.category].push(poc);
        return acc;
    }, {} as Record<string, AttackChainPoc[]>);

    return (
        <div className="pb-20">
            <header className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 py-8 transition-colors duration-300">
                <div className="container mx-auto px-4">
                    <h1 className="text-3xl font-bold bg-gradient-to-r from-purple-600 to-pink-600 dark:from-purple-400 dark:to-pink-400 bg-clip-text text-transparent flex items-center gap-3">
                        <Workflow className="w-8 h-8 text-purple-600 dark:text-purple-400" />
                        Attack Chains Library
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400 mt-2">
                        按漏洞类型归档自动化攻击链脚本，支持检索、编辑、执行与复用利用流程。
                    </p>
                </div>
            </header>

            <main className="container mx-auto px-4 py-8">
                {loading ? (
                    <div className="flex justify-center items-center h-64">
                        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-purple-500"></div>
                    </div>
                ) : Object.keys(grouped).length === 0 ? (
                    <div className="text-center py-12 text-slate-500">
                        No attack chains found.
                    </div>
                ) : (
                    <div className="space-y-12">
                        {Object.entries(grouped).map(([category, items]) => (
                            <section key={category} className="space-y-4">
                                <div className="flex items-center gap-2 border-b border-slate-200 dark:border-slate-800 pb-2">
                                    <Tag className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                                    <h2 className="text-2xl font-semibold text-slate-800 dark:text-slate-100 capitalize">{category}</h2>
                                    <span className="text-sm bg-slate-100 dark:bg-slate-800 text-slate-600 dark:text-slate-400 px-2 py-0.5 rounded-full">
                                        {items.length}
                                    </span>
                                </div>

                                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                                    {items.map((poc) => (
                                        <div
                                            key={`${poc.category}-${poc.name}-${poc.filename}`}
                                            onClick={() => handlePocClick(poc)}
                                            className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-5 hover:border-purple-500/50 hover:bg-purple-50 dark:hover:bg-slate-800/50 transition-all cursor-pointer group shadow-sm hover:shadow-md"
                                        >
                                            <div className="flex items-start justify-between">
                                                <div className="flex items-center gap-3">
                                                    <div className="p-2 bg-slate-100 dark:bg-slate-800 rounded-lg group-hover:bg-purple-500/20 group-hover:text-purple-600 dark:group-hover:text-purple-400 text-slate-600 dark:text-slate-400 transition-colors">
                                                        <FileCode className="w-6 h-6" />
                                                    </div>
                                                    <div>
                                                        <h3 className="font-medium text-slate-800 dark:text-slate-200 group-hover:text-purple-700 dark:group-hover:text-white transition-colors">
                                                            {poc.name}
                                                        </h3>
                                                        <p className="text-xs text-slate-500 font-mono mt-1">
                                                            {poc.filename}
                                                        </p>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                    ))}
                                </div>
                            </section>
                        ))}
                    </div>
                )}
            </main>

            {/* Code Modal */}
            {selectedPoc && (
                <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
                    <div className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-xl w-full max-w-4xl max-h-[85vh] flex flex-col shadow-2xl animate-in zoom-in-95 duration-200">
                        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-900/50 rounded-t-xl">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-purple-100 dark:bg-purple-500/10 rounded-lg text-purple-600 dark:text-purple-400">
                                    <FileCode className="w-5 h-5" />
                                </div>
                                <div>
                                    <h3 className="font-semibold text-slate-900 dark:text-slate-100">
                                        {selectedPoc.name}
                                    </h3>
                                    <div className="flex items-center gap-2 mt-1">
                                        <p className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                                            {selectedPoc.category} / {selectedPoc.filename}
                                        </p>
                                    </div>
                                </div>
                            </div>

                            {/* Tabs */}
                            <div className="flex bg-slate-100 dark:bg-slate-800/50 rounded-lg p-1">
                                <button
                                    onClick={() => setActiveTab('code')}
                                    className={`px-4 py-1.5 text-sm font-medium rounded-md transition-all ${activeTab === 'code'
                                        ? 'bg-white dark:bg-slate-700 text-slate-900 dark:text-white shadow-sm'
                                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                                        }`}
                                >
                                    Code
                                </button>
                                <button
                                    onClick={() => setActiveTab('run')}
                                    className={`px-4 py-1.5 text-sm font-medium rounded-md transition-all flex items-center gap-2 ${activeTab === 'run'
                                        ? 'bg-purple-50 dark:bg-purple-600/20 text-purple-700 dark:text-purple-300 shadow-sm'
                                        : 'text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-slate-200'
                                        }`}
                                >
                                    <Terminal className="w-3 h-3" />
                                    Execute
                                </button>
                            </div>

                            <div className="flex items-center gap-2">
                                {activeTab === 'code' && (
                                    <>
                                        {!isEditing ? (
                                            <>
                                                <button
                                                    onClick={() => {
                                                        if (selectedPoc.content)
                                                            navigator.clipboard.writeText(selectedPoc.content);
                                                    }}
                                                    className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
                                                    title="Copy Code"
                                                >
                                                    <Copy className="w-5 h-5" />
                                                </button>
                                                <button
                                                    onClick={handleEdit}
                                                    className="p-2 hover:bg-slate-100 dark:hover:bg-slate-800 rounded-lg text-slate-500 dark:text-slate-400 hover:text-slate-900 dark:hover:text-white transition-colors"
                                                    title="Edit Code"
                                                >
                                                    <Edit className="w-5 h-5" />
                                                </button>
                                            </>
                                        ) : (
                                            <>
                                                <button
                                                    onClick={handleSave}
                                                    disabled={saving}
                                                    className="px-3 py-1.5 bg-purple-600 hover:bg-purple-700 text-white rounded-md text-sm font-medium flex items-center gap-2 transition-colors disabled:opacity-50"
                                                >
                                                    {saving ? <Loader2 className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                                                    Save
                                                </button>
                                                <button
                                                    onClick={handleCancelEdit}
                                                    disabled={saving}
                                                    className="px-3 py-1.5 bg-slate-200 dark:bg-slate-700 hover:bg-slate-300 dark:hover:bg-slate-600 text-slate-700 dark:text-slate-200 rounded-md text-sm font-medium transition-colors"
                                                >
                                                    Cancel
                                                </button>
                                            </>
                                        )}
                                    </>
                                )}
                                <div className="h-6 w-px bg-slate-200 dark:bg-slate-700 mx-1"></div>
                                <button
                                    onClick={() => setSelectedPoc(null)}
                                    className="p-2 hover:bg-red-100 dark:hover:bg-red-500/10 hover:text-red-600 dark:hover:text-red-400 rounded-lg text-slate-500 dark:text-slate-400 transition-colors"
                                >
                                    <X className="w-6 h-6" />
                                </button>
                            </div>
                        </div>

                        <div className="flex-1 overflow-auto bg-slate-50 dark:bg-slate-950 font-mono text-sm relative flex flex-col">
                            {activeTab === 'code' ? (
                                <div className="p-4">
                                    {loadingContent ? (
                                        <div className="flex flex-col items-center justify-center p-12 text-slate-500 gap-2">
                                            <Loader2 className="w-8 h-8 animate-spin text-purple-500" />
                                            <span>Loading content...</span>
                                        </div>
                                    ) : isEditing ? (
                                        <textarea
                                            value={editedContent}
                                            onChange={(e) => setEditedContent(e.target.value)}
                                            className="w-full h-[60vh] bg-slate-50 dark:bg-slate-950 text-slate-800 dark:text-slate-300 font-mono text-sm p-2 outline-none resize-none"
                                            spellCheck={false}
                                        />
                                    ) : (
                                        <div className="rounded-lg overflow-hidden border border-slate-200 dark:border-slate-800 shadow-sm">
                                            {/* Code Window Header */}
                                            <div className="bg-slate-100 dark:bg-[#1e1e1e] border-b border-slate-200 dark:border-slate-800 px-4 py-2 flex items-center justify-between">
                                                <div className="flex items-center gap-2">
                                                    <div className="flex gap-1.5">
                                                        <div className="w-3 h-3 rounded-full bg-red-400/80 hover:bg-red-500 transition-colors"></div>
                                                        <div className="w-3 h-3 rounded-full bg-yellow-400/80 hover:bg-yellow-500 transition-colors"></div>
                                                        <div className="w-3 h-3 rounded-full bg-green-400/80 hover:bg-green-500 transition-colors"></div>
                                                    </div>
                                                    <span className="ml-4 text-xs font-mono text-slate-500 opacity-70">
                                                        {selectedPoc.filename}
                                                    </span>
                                                </div>
                                                <div className="text-xs text-slate-400">
                                                    {getLanguage(selectedPoc.filename).toUpperCase()}
                                                </div>
                                            </div>

                                            <SyntaxHighlighter
                                                language={getLanguage(selectedPoc.filename)}
                                                style={vscDarkPlus}
                                                customStyle={{
                                                    margin: 0,
                                                    padding: '1.5rem',
                                                    fontSize: '0.9rem',
                                                    lineHeight: '1.5',
                                                    background: '#1e1e1e', // Force dark background to match theme
                                                }}
                                                showLineNumbers={true}
                                                wrapLines={true}
                                            >
                                                {selectedPoc.content || "No content loaded."}
                                            </SyntaxHighlighter>
                                        </div>
                                    )}
                                </div>
                            ) : (
                                <div className="flex flex-col h-full bg-white dark:bg-[#0d1117]">
                                    <div className="p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-900/30">

                                        {/* Go-specific controls */}
                                        {selectedPoc.filename.endsWith('.go') && (
                                            <div className="grid grid-cols-2 gap-4 mb-4 p-4 bg-slate-100 dark:bg-slate-800/50 rounded-lg border border-slate-200 dark:border-slate-800">
                                                <div>
                                                    <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">
                                                        Target OS
                                                    </label>
                                                    <select
                                                        value={goOS}
                                                        onChange={(e) => setGoOS(e.target.value)}
                                                        className="w-full bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md px-3 py-1.5 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                                                    >
                                                        <option value="linux">Linux</option>
                                                        <option value="windows">Windows</option>
                                                        <option value="darwin">macOS (Darwin)</option>
                                                    </select>
                                                </div>
                                                <div>
                                                    <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-1">
                                                        Target Arch
                                                    </label>
                                                    <select
                                                        value={goArch}
                                                        onChange={(e) => setGoArch(e.target.value)}
                                                        className="w-full bg-white dark:bg-slate-700 border border-slate-300 dark:border-slate-600 rounded-md px-3 py-1.5 text-sm text-slate-900 dark:text-slate-100 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                                                    >
                                                        <option value="amd64">amd64 (x64)</option>
                                                        <option value="386">386 (x86)</option>
                                                        <option value="arm64">arm64</option>
                                                    </select>
                                                </div>
                                            </div>
                                        )}

                                        <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2 uppercase tracking-wider">
                                            Command Preview
                                        </label>
                                        <div className="flex items-center gap-2 font-mono text-slate-600 dark:text-slate-300 bg-slate-100 dark:bg-black/50 p-3 rounded-lg border border-slate-200 dark:border-slate-800 mb-4 whitespace-nowrap overflow-x-auto">
                                            {selectedPoc.filename.endsWith('.go') ? (
                                                <>
                                                    <span className="text-orange-600 dark:text-orange-400 mr-2">
                                                        GOOS={goOS} GOARCH={goArch}
                                                    </span>
                                                    <span className="text-purple-600 dark:text-purple-400">go build</span>
                                                    <span className="text-slate-500">-o {selectedPoc.name}</span>
                                                    <span className="text-blue-600 dark:text-blue-400">{selectedPoc.filename}</span>
                                                    <span className="text-slate-500 dark:text-slate-400 ml-2">{osSeparator}</span>
                                                    <span className="text-green-600 dark:text-green-400 ml-2">./{selectedPoc.name}</span>
                                                    <span className="text-slate-700 dark:text-slate-200 ml-2">{runArgs}</span>
                                                </>
                                            ) : (
                                                <>
                                                    <span className="text-purple-600 dark:text-purple-400">python</span>
                                                    <span className="text-blue-600 dark:text-blue-400">{selectedPoc.filename}</span>
                                                    <span className="text-slate-700 dark:text-slate-200">{runArgs}</span>
                                                </>
                                            )}
                                        </div>

                                        <label className="block text-xs font-semibold text-slate-500 dark:text-slate-400 mb-2 uppercase tracking-wider">
                                            Arguments
                                        </label>
                                        <p className="text-xs text-slate-500 mb-2">
                                            {getCategoryHints(selectedPoc.category).tip}
                                        </p>
                                        <div className="flex gap-2">
                                            <input
                                                type="text"
                                                value={runArgs}
                                                onChange={(e) => setRunArgs(e.target.value)}
                                                placeholder={getCategoryHints(selectedPoc.category).placeholder}
                                                className="flex-1 bg-white dark:bg-slate-800 border-slate-300 dark:border-slate-700 rounded-lg px-4 py-2 text-slate-900 dark:text-slate-200 placeholder:text-slate-400 dark:placeholder:text-slate-600 focus:outline-none focus:ring-2 focus:ring-purple-500/50"
                                                onKeyDown={(e) => {
                                                    if (e.key === 'Enter' && !running) handleRun();
                                                }}
                                            />
                                            <button
                                                onClick={handleRun}
                                                disabled={running}
                                                className="px-6 py-2 bg-purple-600 hover:bg-purple-500 text-white font-medium rounded-lg transition-colors flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed shadow-md hover:shadow-lg"
                                            >
                                                {running ? (
                                                    <Loader2 className="w-4 h-4 animate-spin" />
                                                ) : (
                                                    <Play className="w-4 h-4" />
                                                )}
                                                Run
                                            </button>
                                        </div>
                                    </div>

                                    <div className="flex-1 p-4 overflow-auto bg-slate-50 dark:bg-[#0d1117] border-t border-slate-200 dark:border-slate-800">
                                        {runOutput ? (
                                            <div>
                                                {runOutput.stdout && (
                                                    <div className="mb-4">
                                                        <div className="text-xs text-green-600 dark:text-green-500 mb-1 font-semibold">STDOUT</div>
                                                        <pre className="text-slate-800 dark:text-slate-300 whitespace-pre-wrap break-all">{runOutput.stdout}</pre>
                                                    </div>
                                                )}
                                                {runOutput.stderr && (
                                                    <div className="mb-4">
                                                        <div className="text-xs text-red-600 dark:text-red-500 mb-1 font-semibold">STDERR</div>
                                                        <pre className="text-red-600 dark:text-red-300 whitespace-pre-wrap break-all">{runOutput.stderr}</pre>
                                                    </div>
                                                )}
                                                <div className="mt-4 pt-4 border-t border-slate-200 dark:border-slate-800 text-xs text-slate-500">
                                                    Process finished with exit code {runOutput.returncode}
                                                </div>
                                            </div>
                                        ) : (
                                            <div className="h-full flex flex-col items-center justify-center text-slate-500 dark:text-slate-600">
                                                <Terminal className="w-12 h-12 mb-4 opacity-20" />
                                                <p>Enter arguments and click run to execute the script.</p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )
            }
        </div >
    );
}
