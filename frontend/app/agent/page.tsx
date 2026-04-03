"use client";

import React, { useState, useEffect, useRef } from 'react';
import { Save, Settings, Bot, TerminalSquare, Search, RefreshCw, KeyRound, Globe, HardDrive, Square, ChevronDown, ChevronRight, Clock, X, Calendar } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

export default function AgentPage() {
    const [apiKey, setApiKey] = useState('');
    const [baseUrl, setBaseUrl] = useState('');
    const [modelName, setModelName] = useState('');
    const [saveStatus, setSaveStatus] = useState<'idle' | 'saving' | 'success' | 'error'>('idle');

    const [target, setTarget] = useState('');
    const [targetUrl, setTargetUrl] = useState('http://localhost:8080');
    const [generating, setGenerating] = useState(false);
    const [logs, setLogs] = useState<string[]>([]);
    const [payload, setPayload] = useState('');
    const [errorMsg, setErrorMsg] = useState('');
    const [logsExpanded, setLogsExpanded] = useState(false);
    const abortControllerRef = useRef<AbortController | null>(null);

    // History state
    const [isHistoryOpen, setIsHistoryOpen] = useState(false);
    const [historyRecords, setHistoryRecords] = useState<any[]>([]);
    const [loadingHistory, setLoadingHistory] = useState(false);

    const fetchHistory = async () => {
        setLoadingHistory(true);
        try {
            const res = await fetch('/api/agent/history');
            const data = await res.json();
            if (data.status === 'success') {
                setHistoryRecords(data.data || []);
            }
        } catch (e) {
            console.error("Failed to fetch history", e);
        } finally {
            setLoadingHistory(false);
        }
    };

    // Fetch initial config
    useEffect(() => {
        fetch('/api/agent/config')
            .then(res => res.json())
            .then(data => {
                if (data.status === 'success') {
                    setApiKey(data.api_key || '');
                    setBaseUrl(data.base_url || '');
                    setModelName(data.model_name || '');
                }
            })
            .catch(err => console.error("Failed to fetch agent config", err));
    }, []);

    const handleSaveConfig = async () => {
        setSaveStatus('saving');
        try {
            const res = await fetch('/api/agent/config', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({
                    api_key: apiKey,
                    base_url: baseUrl,
                    model_name: modelName,
                }),
            });
            if (res.ok) {
                setSaveStatus('success');
                setTimeout(() => setSaveStatus('idle'), 2000);
            } else {
                setSaveStatus('error');
            }
        } catch (e) {
            console.error(e);
            setSaveStatus('error');
        }
    };

    const handleGenerate = async () => {
        if (!target.trim()) {
            setErrorMsg("Please enter a target CVE or App name.");
            return;
        }

        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
        }
        const abortController = new AbortController();
        abortControllerRef.current = abortController;

        setGenerating(true);
        setLogsExpanded(true);
        setErrorMsg('');
        setPayload('');
        setLogs([]);

        try {
            const res = await fetch('/api/agent/generate', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'text/event-stream'
                },
                signal: abortController.signal,
                body: JSON.stringify({
                    target: target,
                    target_url: targetUrl,
                    api_key: apiKey.includes('***') ? undefined : apiKey,
                    base_url: baseUrl,
                    model_name: modelName,
                }),
            });

            if (!res.ok || !res.body) {
                const errData = await res.json().catch(() => ({}));
                setErrorMsg(errData.detail || 'Error connecting to Agent Hub');
                setGenerating(false);
                return;
            }

            const reader = res.body.getReader();
            const decoder = new TextDecoder('utf-8');

            while (true) {
                const { done, value } = await reader.read();
                if (done) break;

                const chunk = decoder.decode(value, { stream: true });
                const lines = chunk.split('\n');

                for (const line of lines) {
                    if (line.startsWith('data: ')) {
                        try {
                            const dataStr = line.replace('data: ', '').trim();
                            if (!dataStr) continue;
                            const data = JSON.parse(dataStr);

                            if (data.type === 'status') {
                                setLogs(prev => [...prev, `[STATUS] ${data.content}`]);
                            } else if (data.type === 'log') {
                                setLogs(prev => [...prev, data.content]);
                            } else if (data.type === 'payload_chunk') {
                                setPayload(prev => {
                                    // If we are starting a new attempt (chunk 1) and we haven't added the header yet
                                    if (data.attempt && data.attempt > 1 && !prev.includes(`### Attempt ${data.attempt}`)) {
                                        return prev + '\n\n---\n\n### Attempt ' + data.attempt + '\n\n' + data.content;
                                    }
                                    return prev + data.content;
                                });
                            } else if (data.type === 'payload') {
                                // Ignore the final payload event if we are streaming chunks, or just set it
                                // if it's the first attempt to ensure completeness
                                if (!data.attempt || data.attempt === 1) {
                                    setPayload(data.content);
                                }
                            } else if (data.type === 'error') {
                                setErrorMsg(data.content);
                            } else if (data.type === 'done') {
                                setGenerating(false);
                                setLogsExpanded(false);
                            }
                        } catch (e) {
                            console.error("Stream parse error", e, line);
                        }
                    }
                }
            }
        } catch (e: any) {
            if (e.name === 'AbortError') {
                setLogs(prev => [...prev, '[SYSTEM] Agent execution stopped by user.']);
                setGenerating(false);
                setLogsExpanded(false);
                return;
            }
            setErrorMsg(e.message || 'Network error');
            setGenerating(false);
            setLogsExpanded(false);
        }
    };

    const handleStop = () => {
        if (abortControllerRef.current) {
            abortControllerRef.current.abort();
            abortControllerRef.current = null;
        }
    };

    return (
        <div className="container mx-auto px-4 py-8">
            <div className="mb-8 border-b border-slate-200 dark:border-slate-800 pb-6 flex items-center justify-between">
                <div>
                    <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2 flex items-center gap-3">
                        <Bot className="w-8 h-8 text-blue-500" />
                        AI Payload Generator
                    </h1>
                    <p className="text-slate-500 dark:text-slate-400">
                        基于本地 Vulhub 文档与漏洞上下文，自动生成可执行的攻击脚本与 Payload。
                    </p>
                </div>
                <button
                    onClick={() => {
                        setIsHistoryOpen(true);
                        fetchHistory();
                    }}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg text-sm font-medium transition-colors border border-slate-200 dark:border-slate-700"
                >
                    <Clock className="w-4 h-4" />
                    History Logs
                </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">

                {/* Left Column: Config & Input */}
                <div className="lg:col-span-1 space-y-6">

                    {/* Target Configuration */}
                    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
                        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 text-slate-800 dark:text-slate-200">
                            <Search className="w-5 h-5 text-indigo-500" />
                            Target Selection
                        </h2>
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">CVE or App Name</label>
                                <input
                                    type="text"
                                    placeholder="e.g., CVE-2017-10271 or weblogic"
                                    value={target}
                                    onChange={e => setTarget(e.target.value)}
                                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-slate-950 dark:border-slate-700 dark:text-slate-200"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1">Target URL</label>
                                <input
                                    type="text"
                                    placeholder="http://127.0.0.1:8080"
                                    value={targetUrl}
                                    onChange={e => setTargetUrl(e.target.value)}
                                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-slate-950 dark:border-slate-700 dark:text-slate-200"
                                />
                            </div>

                            <div className="flex gap-2">
                                <button
                                    onClick={handleGenerate}
                                    disabled={generating}
                                    className={`flex-1 py-2.5 rounded-lg flex justify-center items-center gap-2 text-sm font-medium text-white transition-all
                    ${generating ? 'bg-indigo-400 cursor-not-allowed' : 'bg-indigo-600 hover:bg-indigo-700 shadow-md hover:shadow-lg'}`}
                                >
                                    {generating ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Bot className="w-4 h-4" />}
                                    {generating ? 'Synthesizing...' : 'Generate Payload'}
                                </button>
                                {generating && (
                                    <button
                                        onClick={handleStop}
                                        className="px-4 py-2.5 rounded-lg flex justify-center items-center gap-2 text-sm font-medium text-white bg-red-500 hover:bg-red-600 shadow-md hover:shadow-lg transition-all"
                                        title="Stop Thinking"
                                    >
                                        <Square className="w-4 h-4 fill-current" />
                                    </button>
                                )}
                            </div>

                            {errorMsg && (
                                <div className="p-3 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 rounded-lg text-sm border border-red-100 dark:border-red-800/30">
                                    {errorMsg}
                                </div>
                            )}
                        </div>
                    </div>

                    {/* Model Configuration */}
                    <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 p-6 shadow-sm">
                        <h2 className="text-xl font-semibold mb-4 flex items-center gap-2 text-slate-800 dark:text-slate-200">
                            <Settings className="w-5 h-5 text-slate-500" />
                            LLM Configuration
                        </h2>
                        <div className="space-y-4">
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
                                    <KeyRound className="w-3 h-3" /> API Key
                                </label>
                                <input
                                    type="password"
                                    placeholder="sk-..."
                                    value={apiKey}
                                    onChange={e => setApiKey(e.target.value)}
                                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-slate-950 dark:border-slate-700 dark:text-slate-200"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
                                    <Globe className="w-3 h-3" /> Base URL
                                </label>
                                <input
                                    type="text"
                                    placeholder="https://api.moonshot.cn/v1"
                                    value={baseUrl}
                                    onChange={e => setBaseUrl(e.target.value)}
                                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-slate-950 dark:border-slate-700 dark:text-slate-200"
                                />
                            </div>
                            <div>
                                <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 flex items-center gap-1">
                                    <HardDrive className="w-3 h-3" /> Model Name
                                </label>
                                <input
                                    type="text"
                                    placeholder="moonshot-v1-8k"
                                    value={modelName}
                                    onChange={e => setModelName(e.target.value)}
                                    className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-900 focus:ring-2 focus:ring-blue-500 focus:border-blue-500 dark:bg-slate-950 dark:border-slate-700 dark:text-slate-200"
                                />
                            </div>

                            <button
                                onClick={handleSaveConfig}
                                disabled={saveStatus === 'saving'}
                                className="w-full flex items-center justify-center gap-2 px-4 py-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-200 rounded-lg text-sm font-medium transition-colors border border-slate-200 dark:border-slate-700"
                            >
                                {saveStatus === 'saving' ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Save className="w-4 h-4" />}
                                {saveStatus === 'success' ? 'Saved!' : 'Save Config'}
                            </button>
                        </div>
                    </div>

                </div>

                {/* Right Column: Payload Output */}
                <div className="lg:col-span-2">
                    <div className="bg-slate-50 dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-800 shadow-sm overflow-hidden h-full min-h-[500px] flex flex-col transition-colors">
                        <div className="flex items-center justify-between px-4 py-3 bg-slate-100 dark:bg-slate-950 border-b border-slate-200 dark:border-slate-800 transition-colors">
                            <div className="flex items-center gap-2 text-slate-700 dark:text-slate-300 font-mono text-sm">
                                <TerminalSquare className="w-4 h-4 text-emerald-500 dark:text-emerald-400" />
                                Generated Answers
                            </div>
                            {payload && (
                                <button
                                    onClick={() => navigator.clipboard.writeText(payload)}
                                    className="text-xs px-2 py-1 bg-white dark:bg-slate-800 hover:bg-slate-200 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 border border-slate-200 dark:border-slate-700 rounded transition-colors shadow-sm"
                                >
                                    Copy Code
                                </button>
                            )}
                        </div>

                        <div className="p-4 flex-1 overflow-auto bg-white dark:bg-[#0d1117] transition-colors flex flex-col space-y-4">
                            {/* Streaming Logs (Collapsible) */}
                            {logs.length > 0 && (
                                <div className="mb-4 border border-slate-200 dark:border-slate-800 rounded-lg overflow-hidden opacity-80 hover:opacity-100 transition-opacity">
                                    <button
                                        onClick={() => setLogsExpanded(!logsExpanded)}
                                        className="w-full flex items-center justify-between px-3 py-2 bg-slate-50 dark:bg-slate-900/50 text-xs font-medium text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300"
                                    >
                                        <div className="flex items-center gap-2">
                                            {generating ? <RefreshCw className="w-3 h-3 animate-spin" /> : <TerminalSquare className="w-3 h-3" />}
                                            Agent Thinking Process {generating ? '(Running...)' : '(Completed)'}
                                        </div>
                                        {logsExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                                    </button>

                                    {logsExpanded && (
                                        <div className="p-3 bg-slate-100/50 dark:bg-slate-950/50 max-h-64 overflow-y-auto space-y-1 border-t border-slate-200 dark:border-slate-800 text-[11px] font-mono text-slate-500 dark:text-slate-400">
                                            {logs.map((log, idx) => (
                                                <div key={idx} className={`${log.includes('[STATUS]') ? 'text-indigo-500 dark:text-indigo-400 font-semibold mt-2 mb-1' : ''}`}>
                                                    {log}
                                                </div>
                                            ))}
                                            {generating && (
                                                <div className="flex items-center gap-2 text-indigo-500 animate-pulse mt-2">
                                                    <div className="w-1.5 h-1.5 rounded-full bg-indigo-500"></div>
                                                    Thinking...
                                                </div>
                                            )}
                                        </div>
                                    )}
                                </div>
                            )}

                            {/* Final Payload */}
                            {payload && (
                                <div className="border-t border-slate-100 dark:border-slate-800 pt-4 mt-auto">
                                    <div className="prose prose-sm dark:prose-invert max-w-none prose-pre:bg-[#1e1e1e] prose-pre:p-0 prose-pre:m-0 w-full overflow-x-hidden p-2 prose-headings:text-slate-800 dark:prose-headings:text-slate-200">
                                        <ReactMarkdown
                                            remarkPlugins={[remarkGfm]}
                                            components={{
                                                code({ node, inline, className, children, ...props }: any) {
                                                    const match = /language-(\w+)/.exec(className || '');
                                                    return !inline && match ? (
                                                        <SyntaxHighlighter
                                                            {...props}
                                                            style={vscDarkPlus as any}
                                                            language={match[1]}
                                                            PreTag="div"
                                                            showLineNumbers={true}
                                                            wrapLongLines={false}
                                                            customStyle={{
                                                                margin: 0,
                                                                borderRadius: '0.375rem',
                                                                fontSize: '0.85rem',
                                                                padding: '1rem'
                                                            }}
                                                        >
                                                            {String(children).replace(/\n$/, '')}
                                                        </SyntaxHighlighter>
                                                    ) : (
                                                        <code {...props} className={`${className} bg-slate-100 dark:bg-slate-800 text-purple-600 dark:text-purple-400 px-1 py-0.5 rounded text-xs font-mono`}>
                                                            {children}
                                                        </code>
                                                    );
                                                }
                                            }}
                                        >
                                            {payload}
                                        </ReactMarkdown>
                                    </div>
                                </div>
                            )}

                            {!payload && !generating && logs.length === 0 && (
                                <div className="h-full flex flex-col items-center justify-center text-slate-400 dark:text-slate-600 space-y-4 my-auto">
                                    <Bot className="w-12 h-12 opacity-20" />
                                    <p className="text-center">Enter a target and click Generate to start the Multi-Agent synthesis process.</p>
                                </div>
                            )}
                        </div>
                    </div>
                </div>

            </div>

            {/* History Drawer */}
            {isHistoryOpen && (
                <>
                    {/* Backdrop */}
                    <div
                        className="fixed inset-0 bg-slate-900/50 backdrop-blur-sm z-40 transition-opacity"
                        onClick={() => setIsHistoryOpen(false)}
                    />

                    {/* Drawer Plate */}
                    <div className="fixed inset-y-0 right-0 w-full md:w-96 bg-white dark:bg-slate-900 shadow-2xl z-50 transform transition-transform border-l border-slate-200 dark:border-slate-800 flex flex-col">
                        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-800">
                            <h2 className="text-lg font-semibold flex items-center gap-2 text-slate-800 dark:text-slate-200">
                                <Clock className="w-5 h-5 text-indigo-500" />
                                Run History
                            </h2>
                            <button
                                onClick={() => setIsHistoryOpen(false)}
                                className="p-1 text-slate-500 hover:text-slate-800 dark:hover:text-slate-200 transition-colors"
                            >
                                <X className="w-5 h-5" />
                            </button>
                        </div>

                        <div className="flex-1 overflow-y-auto p-4 space-y-3 bg-slate-50 dark:bg-slate-950">
                            {loadingHistory ? (
                                <div className="flex items-center justify-center p-8 text-slate-500">
                                    <RefreshCw className="w-5 h-5 animate-spin" />
                                </div>
                            ) : historyRecords.length === 0 ? (
                                <div className="text-center p-8 text-slate-500 dark:text-slate-400 text-sm">
                                    No generation history found.
                                </div>
                            ) : (
                                historyRecords.map((record, idx) => (
                                    <div
                                        key={idx}
                                        onClick={() => {
                                            setTarget(record.cve_name);
                                            setTargetUrl(record.target_url);
                                            setPayload(record.payload_script);
                                            setLogs(record.logs || []);
                                            setIsHistoryOpen(false);
                                            setLogsExpanded(false); // keep closed to prioritize payload
                                            window.scrollTo({ top: 0, behavior: 'smooth' });
                                        }}
                                        className="bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-800 rounded-lg p-4 cursor-pointer hover:border-indigo-500/50 hover:shadow-md transition-all group"
                                    >
                                        <div className="flex items-start justify-between mb-2">
                                            <div className="font-semibold text-slate-800 dark:text-slate-200 truncate pr-2 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">
                                                {record.cve_name}
                                            </div>
                                            <div className="text-[10px] text-slate-400 font-mono whitespace-nowrap">
                                                {new Date(record.timestamp).toLocaleTimeString()}
                                            </div>
                                        </div>
                                        <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400 mb-2">
                                            <Globe className="w-3 h-3" />
                                            <span className="truncate">{record.target_url}</span>
                                        </div>
                                        <div className="flex items-center gap-1.5 text-xs text-slate-400 dark:text-slate-500">
                                            <Calendar className="w-3 h-3" />
                                            <span>{new Date(record.timestamp).toLocaleDateString()}</span>
                                        </div>
                                    </div>
                                ))
                            )}
                        </div>
                    </div>
                </>
            )}
        </div>
    );
}
