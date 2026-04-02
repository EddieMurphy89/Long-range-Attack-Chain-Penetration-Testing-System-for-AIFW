"use client";
import React, { useEffect, useState } from 'react';
import { fetcher, post } from '@/lib/api';
import { Layers, RotateCw, Power, PowerOff, RefreshCw } from 'lucide-react';

interface Container {
    id: string;
    name: string;
    ip: string;
    status: string; // 'running', 'exited', etc.
    status_raw?: string; // original docker status string, if provided
    zone: string;
}

interface ZoneData {
    external: Container[];
    dmz: Container[];
    database: Container[];
    intranet: Container[];
    aifw: Container[];
}

export default function ZoneManager() {
    const [zones, setZones] = useState<ZoneData>({ external: [], dmz: [], database: [], intranet: [], aifw: [] });
    const [loading, setLoading] = useState(false);
    const [actionLoading, setActionLoading] = useState<string | null>(null);

    const normalizeStatus = (status?: string) => {
        if (!status) return 'unknown';
        const s = status.trim().toLowerCase();
        if (s === 'running' || s.startsWith('up')) return 'running';
        if (s.startsWith('exited')) return 'exited';
        if (s.startsWith('created')) return 'created';
        if (s.startsWith('paused') || s.includes('paused')) return 'paused';
        if (s.startsWith('restarting') || s.includes('restarting')) return 'restarting';
        if (s.startsWith('dead')) return 'dead';
        if (s.startsWith('removed') || s.startsWith('removal')) return 'removed';
        return s.split(' ')[0];
    };

    useEffect(() => {
        loadZones();
        const interval = setInterval(loadZones, 5000);
        return () => clearInterval(interval);
    }, []);

    const loadZones = async () => {
        try {
            const data = await fetcher('/api/zones/containers?include_stopped=true');
            setZones(data);
        } catch (e) {
            console.error(e);
        }
    };

    const handleAction = async (cid: string, action: 'start' | 'stop' | 'restart') => {
        setActionLoading(cid);
        try {
            await post('/api/containers/action', { container_id: cid, action });
            await loadZones();
        } catch (e: any) {
            alert('Action failed: ' + e.message);
        } finally {
            setActionLoading(null);
        }
    };

    const ZoneColumn = ({ title, containers, colorClass }: { title: string, containers: Container[], colorClass: string }) => (
        <div className="bg-slate-50 dark:bg-slate-900/50 rounded-xl border border-slate-200 dark:border-slate-800 p-4 flex flex-col h-full">
            <div className={`flex items-center justify-between mb-4 pb-3 border-b border-slate-200 dark:border-slate-800 ${colorClass}`}>
                <h3 className="font-bold text-slate-700 dark:text-slate-300 uppercase tracking-wide text-sm">{title}</h3>
                <span className="bg-white dark:bg-slate-800 px-2 py-0.5 rounded text-xs font-bold border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-300">{containers.length}</span>
            </div>

            <div className="flex-1 space-y-3">
                {containers.length === 0 && (
                    <div className="h-32 flex items-center justify-center text-slate-400 dark:text-slate-500 text-sm italic border-2 border-dashed border-slate-200 dark:border-slate-800 rounded-lg">
                        No containers
                    </div>
                )}
                {containers.map(c => {
                    const statusNormalized = normalizeStatus(c.status);
                    const isRunning = statusNormalized === 'running';
                    const statusTitle = c.status_raw || c.status || 'unknown';
                    return (
                        <div key={c.id} className="bg-white dark:bg-slate-800 p-3 rounded-lg border border-slate-200 dark:border-slate-700 shadow-sm hover:shadow-md transition-shadow">
                            <div className="flex justify-between items-start mb-2">
                                <span className="font-semibold text-slate-800 dark:text-slate-200 text-sm truncate max-w-[150px]" title={c.name}>{c.name}</span>
                                <div className={`w-2 h-2 rounded-full mt-1.5 ${isRunning ? 'bg-green-500 animate-pulse' : 'bg-slate-300 dark:bg-slate-600'}`} title={statusTitle}></div>
                            </div>
                            <div className="flex flex-wrap gap-1 mb-3">
                                {c.ip ? c.ip.split(',').filter(ip => ip.trim()).map((ip, i) => (
                                    <span key={i} className="text-xs font-mono text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-900/50 px-1.5 py-0.5 rounded border border-slate-100 dark:border-slate-800">
                                        {ip.trim()}
                                    </span>
                                )) : (
                                    <span className="text-xs text-slate-400 italic">No IP</span>
                                )}
                            </div>

                            <div className="flex gap-2">
                                {isRunning ? (
                                    <>
                                        <button
                                            onClick={() => handleAction(c.id, 'restart')}
                                            disabled={actionLoading === c.id}
                                            className="p-1.5 text-blue-600 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded transition-colors disabled:opacity-50" title="Restart"
                                        >
                                            <RefreshCw className={`w-4 h-4 ${actionLoading === c.id ? 'animate-spin' : ''}`} />
                                        </button>
                                        <button
                                            onClick={() => handleAction(c.id, 'stop')}
                                            disabled={actionLoading === c.id}
                                            className="p-1.5 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded transition-colors disabled:opacity-50" title="Stop"
                                        >
                                            <PowerOff className="w-4 h-4" />
                                        </button>
                                    </>
                                ) : (
                                    <button
                                        onClick={() => handleAction(c.id, 'start')}
                                        disabled={actionLoading === c.id}
                                        className="p-1.5 text-green-600 dark:text-green-400 hover:bg-green-50 dark:hover:bg-green-900/20 rounded transition-colors disabled:opacity-50" title="Start"
                                    >
                                        <Power className="w-4 h-4" />
                                    </button>
                                )}
                            </div>
                        </div>
                    );
                })}
            </div>
        </div>
    );

    return (
        <div className="bg-white dark:bg-slate-900 rounded-xl shadow-sm border border-slate-200 dark:border-slate-800 overflow-hidden h-full">
            <div className="px-6 py-4 border-b border-slate-100 dark:border-slate-800 bg-slate-50/50 dark:bg-slate-800/50 flex items-center justify-between">
                <div className="flex items-center gap-2">
                    <Layers className="w-5 h-5 text-purple-600 dark:text-purple-400" />
                    <h2 className="font-bold text-slate-800 dark:text-white">Zone Management Board</h2>
                </div>
                <button onClick={loadZones} className="text-slate-400 hover:text-blue-600 dark:hover:text-blue-400">
                    <RotateCw className="w-4 h-4" />
                </button>
            </div>

            <div className="p-6 grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-6">
                <ZoneColumn title="AIFW Gateway" containers={zones.aifw} colorClass="text-emerald-600" />
                <ZoneColumn title="External Zone" containers={zones.external} colorClass="text-red-600" />
                <ZoneColumn title="DMZ Zone" containers={zones.dmz} colorClass="text-blue-600" />
                <ZoneColumn title="Intranet" containers={zones.intranet} colorClass="text-purple-600" />
                <ZoneColumn title="Database Zone" containers={zones.database} colorClass="text-orange-600" />
            </div>
        </div>
    );
}
