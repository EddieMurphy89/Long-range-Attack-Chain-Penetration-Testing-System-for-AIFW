"use client";
import React, { useEffect, useState } from 'react';
import { VulnInfo, ContainerStatus, post } from '@/lib/api';
import { X, Play, Square, Activity, AlertTriangle, Link as LinkIcon } from 'lucide-react';

interface VulnModalProps {
    vuln: VulnInfo | null;
    onClose: () => void;
}

export default function VulnModal({ vuln, onClose }: VulnModalProps) {
    const [status, setStatus] = useState<ContainerStatus | null>(null);
    const [loading, setLoading] = useState(false);
    const [actionLoading, setActionLoading] = useState(false);
    const [selectedZone, setSelectedZone] = useState('default');
    const [polling, setPolling] = useState(false);
    const [startError, setStartError] = useState<string | null>(null);
    // We should load default subnets from localStorage or API, for now hardcode/placeholder or ignore display

    useEffect(() => {
        if (vuln) {
            checkStatus();
            setSelectedZone('default');
            setPolling(false);
            setStartError(null);
        }
    }, [vuln]);

    const checkStatus = async (silent = false) => {
        if (!vuln) return;
        if (!silent) setLoading(true);
        try {
            const res = await fetch(`/api/vulns/status?path=${vuln.path}`);
            const data = await res.json();
            setStatus(data);
            if (data?.start_task?.state === 'failed') {
                setStartError(data?.start_task?.message || 'Start failed');
            }
            return data;
        } catch (e) {
            console.error(e);
            return null;
        } finally {
            if (!silent) setLoading(false);
        }
    };

    useEffect(() => {
        if (!vuln || !polling) return;
        let cancelled = false;
        let timeoutId: ReturnType<typeof setTimeout> | null = null;

        const poll = async () => {
            if (cancelled) return;
            const data = await checkStatus(true);
            if (cancelled) return;

            if (data?.start_task?.state === 'failed') {
                setPolling(false);
                return;
            }
            if (data?.running) {
                setPolling(false);
                return;
            }

            timeoutId = setTimeout(poll, 3000);
        };

        poll();

        return () => {
            cancelled = true;
            if (timeoutId) clearTimeout(timeoutId);
        };
    }, [polling, vuln]);

    useEffect(() => {
        if (status?.start_task?.state === 'starting' && !polling) {
            setPolling(true);
        }
        if (status?.running) {
            setPolling(false);
            setStartError(null);
        }
        if (status?.start_task?.state === 'failed') {
            setPolling(false);
        }
    }, [status?.start_task?.state, status?.running, polling]);

    const handleAction = async (type: 'start' | 'stop') => {
        if (!vuln) return;
        if (type === 'stop' && !confirm('Are you sure you want to destroy this environment?')) return;

        setActionLoading(true);
        setStartError(null);
        try {
            const endpoint = type === 'start' ? '/api/vulns/start' : '/api/vulns/stop';
            // Start needs extra params
            const body = type === 'start' ? {
                path: vuln.path,
                zone: selectedZone,
                // In a real app we'd fetch these from global config store
                dmz_subnet: "192.168.6.0/24",
                db_subnet: "192.168.5.0/24"
            } : { path: vuln.path };

            // Allow overriding subnets if stored in localStorage (Client Side)
            if (type === 'start') {
                const stored = localStorage.getItem('vulhub_net_config');
                if (stored) {
                    const parsed = JSON.parse(stored);
                    if (parsed.dmzSubnet) body.dmz_subnet = parsed.dmzSubnet;
                    if (parsed.dbSubnet) body.db_subnet = parsed.dbSubnet;
                }
            }

            await post(endpoint, body);
            if (type === 'start') {
                setPolling(true);
            } else {
                setPolling(false);
            }
            await checkStatus(true);
        } catch (e: any) {
            alert(e.message);
        } finally {
            setActionLoading(false);
        }
    };

    if (!vuln) return null;

    const startState = status?.start_task?.state;
    const waitingForContainers = startState === 'success' && !status?.running;
    const isStarting = polling || startState === 'starting' || waitingForContainers;
    const startFailed = startState === 'failed' || !!startError;
    const statusText = loading ? 'Checking status...' :
        startFailed ? 'Start failed' :
            isStarting ? (waitingForContainers ? 'Starting containers...' : 'Pulling images...') :
                status?.running ? 'Environment Running' : 'Environment Stopped';

    return (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50 dark:bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
            <div className="bg-white dark:bg-slate-900 rounded-2xl shadow-2xl w-full max-w-lg overflow-hidden border border-slate-100 dark:border-slate-800">
                <div className="px-6 py-4 border-b border-slate-100 dark:border-slate-800 flex justify-between items-center bg-slate-50/50 dark:bg-slate-900/50">
                    <h3 className="text-lg font-bold text-slate-800 dark:text-slate-100">Environment Control</h3>
                    <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-200 transition-colors">
                        <X className="w-6 h-6" />
                    </button>
                </div>

                <div className="p-6">
                    <div className="mb-6 space-y-4">
                        <div>
                            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">App</label>
                            <div className="text-lg font-semibold text-slate-800 dark:text-slate-200">{vuln.app}</div>
                        </div>
                        <div>
                            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">CVE ID</label>
                            <div className="text-base font-medium text-slate-700 dark:text-slate-300">{vuln.cve}</div>
                        </div>
                        <div>
                            <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">Path</label>
                            <code className="block mt-1 p-2 bg-slate-100 dark:bg-slate-950 rounded text-sm text-slate-600 dark:text-slate-400 font-mono break-all border border-slate-200 dark:border-slate-800">
                                {vuln.path}
                            </code>
                        </div>
                    </div>

                    {/* Status Badge */}
                    <div className={`flex items-center p-3 rounded-lg mb-6 border ${startFailed ? 'bg-red-50 dark:bg-red-900/10 border-red-200 dark:border-red-900/30' :
                        (loading || isStarting) ? 'bg-blue-50 dark:bg-blue-900/10 border-blue-100 dark:border-blue-900/30' :
                            status?.running ? 'bg-green-50 dark:bg-green-900/10 border-green-200 dark:border-green-900/30' :
                                'bg-slate-50 dark:bg-slate-800/50 border-slate-200 dark:border-slate-700'
                        }`}>
                        <div className="relative flex h-3 w-3 mr-3 justify-center items-center">
                            {(loading || isStarting) ? (
                                <svg className="animate-spin h-3 w-3 text-blue-600 dark:text-blue-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                                </svg>
                            ) : (
                                <>
                                    {status?.running && !startFailed && <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-green-400 opacity-75"></span>}
                                    <span className={`relative inline-flex rounded-full h-3 w-3 ${startFailed ? 'bg-red-500' : status?.running ? 'bg-green-500' : 'bg-slate-400'
                                        }`}></span>
                                </>
                            )}
                        </div>
                        <span className={`font-medium ${startFailed ? 'text-red-700 dark:text-red-300' :
                            (loading || isStarting) ? 'text-blue-700 dark:text-blue-300' :
                                status?.running ? 'text-green-700 dark:text-green-400' : 'text-slate-600 dark:text-slate-400'
                            }`}>
                            {statusText}
                        </span>
                    </div>
                    {startFailed && (startError || status?.start_task?.message) && (
                        <div className="mb-6 flex items-start gap-2 text-xs text-red-600 dark:text-red-400">
                            <AlertTriangle className="w-4 h-4 mt-0.5" />
                            <span className="break-words">{startError || status?.start_task?.message}</span>
                        </div>
                    )}

                    {/* Zone Selector (Only when stopped) */}
                    {!status?.running && (
                        <div className="mb-6">
                            <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">Network Zone Deployment</label>
                            <select
                                value={selectedZone}
                                onChange={(e) => setSelectedZone(e.target.value)}
                                className="w-full px-3 py-2 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm text-slate-600 dark:text-slate-300"
                            >
                                <option value="default">Default (Standard)</option>
                                <option value="external">External Zone</option>
                                <option value="dmz">DMZ Zone</option>
                                <option value="intranet">Intranet</option>
                                <option value="database">Database Zone</option>
                            </select>
                            <div className="mt-2 text-xs text-slate-500 dark:text-slate-400 pl-1 border-l-2 border-slate-300 dark:border-slate-600">
                                {selectedZone === 'external' && 'Exposed to Public Internet (DMZ Network).'}
                                {selectedZone === 'dmz' && 'Deploys to exposed DMZ subnet.'}
                                {selectedZone === 'database' && 'Deploys to isolated Database subnet.'}
                                {selectedZone === 'intranet' && 'Connects to both DMZ and DB subnets.'}
                                {selectedZone === 'default' && 'Standard Docker Compose network.'}
                            </div>
                        </div>
                    )}

                    {/* Container Details */}
                    {status?.containers && status.containers.length > 0 && (
                        <div className="mb-6 p-4 bg-slate-50 dark:bg-slate-800/50 rounded-xl border border-slate-100 dark:border-slate-700">
                            <h4 className="text-sm font-bold text-slate-700 dark:text-slate-200 mb-3 flex items-center gap-2">
                                <Activity className="w-4 h-4 text-blue-500 dark:text-blue-400" /> Container Info
                            </h4>
                            <div className="space-y-3">
                                {status.containers.map((c: any) => (
                                    <div key={c.name} className="bg-white dark:bg-slate-900 p-3 rounded-lg border border-slate-200 dark:border-slate-700 shadow-sm text-sm">
                                        <div className="flex justify-between items-center mb-2">
                                            <span className="font-medium truncate mr-2 text-slate-800 dark:text-slate-200">{c.name}</span>
                                            <span className={`text-[10px] px-2 py-0.5 rounded-full uppercase tracking-wide font-bold ${c.status === 'running' ? 'bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400' : 'bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-400'}`}>
                                                {c.status}
                                            </span>
                                        </div>
                                        {c.ports?.map((p: string) => (
                                            <div key={p} className="flex items-center text-blue-600 dark:text-blue-400 text-xs mb-1">
                                                <LinkIcon className="w-3 h-3 mr-1" />
                                                {p.startsWith('127.0.0.1') ? (
                                                    <a href={`http://${p.split(' ->')[0]}`} target="_blank" rel="noopener noreferrer" className="hover:underline">
                                                        {p}
                                                    </a>
                                                ) : (
                                                    <span>{p}</span>
                                                )}
                                            </div>
                                        ))}
                                        {c.ips?.length > 0 && (
                                            <div className="text-xs text-slate-500 dark:text-slate-400 mt-1 font-mono">
                                                IPs: {c.ips.join(', ')}
                                            </div>
                                        )}
                                    </div>
                                ))}
                            </div>
                        </div>
                    )}

                    {/* Actions */}
                    <div className="flex gap-3">
                        <button
                            onClick={() => handleAction('start')}
                            disabled={actionLoading || status?.running || loading || isStarting}
                            className="flex-1 py-2.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-colors shadow-sm"
                        >
                            <Play className="w-4 h-4 fill-current" />
                            {isStarting ? 'Pulling...' : 'Start'}
                        </button>
                        {status?.running && (
                            <button
                                onClick={() => handleAction('stop')}
                                disabled={actionLoading}
                                className="flex-1 py-2.5 bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 border border-red-200 dark:border-red-900/30 rounded-lg font-medium hover:bg-red-100 dark:hover:bg-red-900/30 disabled:opacity-50 disabled:cursor-not-allowed flex items-center justify-center gap-2 transition-colors"
                            >
                                <Square className="w-4 h-4 fill-current" />
                                Destroy
                            </button>
                        )}
                    </div>
                </div>
            </div>
        </div>
    );
}
