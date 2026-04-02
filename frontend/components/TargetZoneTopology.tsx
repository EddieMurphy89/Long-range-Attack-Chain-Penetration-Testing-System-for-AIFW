"use client";
import React, { useEffect, useState, useRef } from 'react';
import { fetcher, startPivotingAttack, getPivotScanResult, verifyCompromise, runLocalExploit, executeCustomExploit, execInteractiveShell, generateAttackReport, getAttackReportHistory, getAttackReportContent } from '@/lib/api';
import { ZoomIn, ZoomOut, Move, Info, X, Skull, Play, Loader2, Terminal, ShieldAlert, FileText, Network, Trash2, Zap, FileSearch, Database, ClipboardCopy, ScrollText, Square, KeyRound, Globe, HardDrive, Clock, Calendar, RefreshCw } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';
import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

const MermaidDiagram = ({ chart }: { chart: string }) => {
    const [svg, setSvg] = useState<string>('');
    const id = useRef(`mermaid-${Math.random().toString(36).substr(2, 9)}`);

    useEffect(() => {
        let isMounted = true;
        import('mermaid').then(m => {
            if (!isMounted) return;
            const mermaid = m.default;
            mermaid.initialize({
                startOnLoad: false,
                theme: 'dark',
                securityLevel: 'loose'
            });
            mermaid.render(id.current, chart).then(result => {
                if (isMounted) setSvg(result.svg);
            }).catch(e => {
                console.error("Mermaid parsing error", e);
                if (isMounted) setSvg(`<div class="text-red-400 p-4 border border-red-900 rounded bg-red-900/20">Failed to render Mermaid diagram</div><pre class="text-xs text-slate-400 mt-2 whitespace-pre-wrap">${chart}</pre>`);
            });
        });
        return () => { isMounted = false; };
    }, [chart]);

    if (!svg) {
        return (
            <div className="flex justify-center items-center my-6 h-32 bg-slate-900 rounded-lg border border-slate-700">
                <Loader2 className="w-6 h-6 animate-spin text-amber-500" />
            </div>
        );
    }

    return <div dangerouslySetInnerHTML={{ __html: svg }} className="not-prose flex justify-center my-6 overflow-x-auto w-full bg-slate-900/50 rounded-lg p-4 border border-slate-800" />;
};

interface ContainerNode {
    id: string;
    name: string;
    ip: string;
    ports: string[]; // e.g. ["80->80"]
    status: string;
    zone: string;
    details?: any;
    image?: string; // Icon logic
    is_compromised?: boolean;
    pwn_type?: string;
    cve_info?: { app: string; cve: string };
}

interface Edge {
    id: string;
    sourceId: string;
    targetId: string;
    status: 'pending' | 'success';
}

interface ShellEntry {
    cmd: string;
    stdout: string;
    stderr: string;
    returncode: number;
}

interface TopologyData {
    external: ContainerNode[];
    dmz: ContainerNode[];
    intranet: ContainerNode[];
    database: ContainerNode[];
}

const FileReadPanel = ({ containerId }: { containerId: string }) => {
    const [path, setPath] = useState('/etc/passwd');
    const [output, setOutput] = useState('');
    const [loading, setLoading] = useState(false);

    const handleRead = async () => {
        if (!path) return;
        setLoading(true);
        try {
            const res = await executeCustomExploit(containerId, path);
            if (res.error) {
                setOutput(`Error: ${res.error}`);
            } else {
                setOutput(res.output || '(No Output)');
            }
        } catch (e: any) {
            setOutput(`Error: ${e.message}`);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="mt-2 text-xs">
            <div className="flex gap-1 mb-1">
                <input
                    className="flex-1 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-600 rounded px-2 py-1 text-slate-700 dark:text-slate-200"
                    value={path}
                    onChange={(e) => setPath(e.target.value)}
                    placeholder="/path/to/file"
                    onClick={(e) => e.stopPropagation()}
                />
                <button
                    disabled={loading}
                    onClick={(e) => { e.stopPropagation(); handleRead(); }}
                    className="bg-orange-500 hover:bg-orange-600 text-white px-2 py-1 rounded disabled:opacity-50"
                >
                    {loading ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileSearch className="w-3 h-3" />}
                </button>
            </div>
            {output && (
                <div
                    className="bg-slate-900 text-green-400 p-2 rounded font-mono text-[10px] max-h-32 overflow-auto whitespace-pre-wrap"
                    onClick={(e) => e.stopPropagation()}
                >
                    {output}
                </div>
            )}
        </div>
    );
};

export default function TargetZoneTopology() {
    const [data, setData] = useState<TopologyData>({ external: [], dmz: [], intranet: [], database: [] });
    const [loading, setLoading] = useState(true);
    const [scale, setScale] = useState(1);
    const [offset, setOffset] = useState({ x: 0, y: 0 });
    const [isDragging, setIsDragging] = useState(false);
    const [dragStart, setDragStart] = useState({ x: 0, y: 0 });
    const [selectedContainer, setSelectedContainer] = useState<ContainerNode | null>(null);
    const [attacking, setAttacking] = useState(false);

    // Edge / Pivot State
    const [edges, setEdges] = useState<Edge[]>([]);
    const [edgeMode, setEdgeMode] = useState(false);
    const [edgeSource, setEdgeSource] = useState<string | null>(null);
    const [isEdgesLoaded, setIsEdgesLoaded] = useState(false);

    // Pivoting State
    const [pivoting, setPivoting] = useState(false);
    const [pivotLogs, setPivotLogs] = useState<string[]>([]);
    const [showLogs, setShowLogs] = useState(false);

    // Scan result viewing
    const [scanResult, setScanResult] = useState<string | null>(null);
    const [showScanResult, setShowScanResult] = useState(false);

    // Interactive Shell State (RCE only)
    const [showShell, setShowShell] = useState(false);
    const [shellTarget, setShellTarget] = useState<ContainerNode | null>(null);
    const [shellCommand, setShellCommand] = useState('');
    const [shellHistory, setShellHistory] = useState<ShellEntry[]>([]);
    const [shellRunning, setShellRunning] = useState(false);
    const [shellWorkdir, setShellWorkdir] = useState('/tmp');

    // Attack Report State
    const [showReportDialog, setShowReportDialog] = useState(false);
    const [showReport, setShowReport] = useState(false);
    const [reportContent, setReportContent] = useState('');
    const [reportGenerating, setReportGenerating] = useState(false);
    const [reportStatus, setReportStatus] = useState('');
    const [reportError, setReportError] = useState('');
    const reportBottomRef = useRef<HTMLDivElement>(null);
    const reportAbortRef = useRef<AbortController | null>(null);
    // Report LLM config (loaded from agent config on first open)
    const [reportApiKey, setReportApiKey] = useState('');
    const [reportBaseUrl, setReportBaseUrl] = useState('');
    const [reportModelName, setReportModelName] = useState('');
    const [reportConfigLoaded, setReportConfigLoaded] = useState(false);

    // Attack Report History State
    const [reportDialogTab, setReportDialogTab] = useState<'new' | 'history'>('new');
    const [reportHistoryRecords, setReportHistoryRecords] = useState<any[]>([]);
    const [loadingHistory, setLoadingHistory] = useState(false);

    const containerRef = useRef<HTMLDivElement>(null);
    const shellBottomRef = useRef<HTMLDivElement>(null);

    // Load edges from localStorage on mount
    useEffect(() => {
        if (typeof window !== 'undefined') {
            const saved = localStorage.getItem('vulhub_targetzone_edges');
            if (saved) {
                try {
                    const parsed = JSON.parse(saved);
                    if (Array.isArray(parsed)) setEdges(parsed);
                } catch (e) {
                    console.error("Failed to load edges", e);
                }
            }
            setIsEdgesLoaded(true);
        }
    }, []);

    // Save edges to localStorage whenever they change
    useEffect(() => {
        if (isEdgesLoaded && typeof window !== 'undefined') {
            localStorage.setItem('vulhub_targetzone_edges', JSON.stringify(edges));
        }
    }, [edges, isEdgesLoaded]);

    useEffect(() => {
        loadData();
        const interval = setInterval(loadData, 5000);
        return () => clearInterval(interval);
    }, []);

    const loadData = async () => {
        try {
            const res = await fetcher('/api/zones/containers');
            // Check for ports info if missing from this endpoint, might need enhancement
            // But main.py now seems to return basic info. 
            // We might need to call /api/vulns/status loop for more details if needed, 
            // but let's assume the zone endpoint provides enough or we enhance it later.
            // Actually `get_zone_containers` in main.py only gives id, name, ip.
            // To get ports, we might need a richer response or merge data.
            // For now, let's just display what we have.
            setData(res);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        if (!edges.length) return;
        let changed = false;
        const newEdges = edges.map(edge => {
            const allNodes = [...data.external, ...data.dmz, ...data.intranet, ...data.database];
            const target = allNodes.find(n => n.id === edge.targetId);
            if (target?.is_compromised && edge.status !== 'success') {
                changed = true;
                return { ...edge, status: 'success' as const };
            }
            return edge;
        });
        if (changed) setEdges(newEdges);
    }, [data, edges]);

    useEffect(() => {
        if (!showShell) return;
        shellBottomRef.current?.scrollIntoView({ behavior: "smooth" });
    }, [shellHistory, shellRunning, showShell]);

    // --- Interaction Handlers ---
    const handleWheel = (e: React.WheelEvent) => {
        if (e.ctrlKey) { // Zoom
            e.preventDefault();
            const delta = e.deltaY > 0 ? 0.9 : 1.1;
            setScale(s => Math.min(Math.max(s * delta, 0.5), 3));
        } else { // Pan
            // Optional: allow wheel pan
        }
    };

    const handleMouseDown = (e: React.MouseEvent) => {
        if ((e.target as HTMLElement).closest('.node-interactive')) return; // Don't drag if clicking a node
        setIsDragging(true);
        setDragStart({ x: e.clientX, y: e.clientY }); // Track raw client coords for drag detection
    };

    const handleMouseMove = (e: React.MouseEvent) => {
        if (isDragging) {
            // Calculate delta from last frame/start
            // Actually, we need to track delta. 
            // Let's stick to simple offset logic but fix click detection.
            setOffset(prev => ({
                x: prev.x + e.movementX,
                y: prev.y + e.movementY
            }));
        }
    };

    const handleMouseUp = (e: React.MouseEvent) => {
        setIsDragging(false);
        // Click detection: if little movement
        const dist = Math.hypot(e.clientX - dragStart.x, e.clientY - dragStart.y);
        if (dist < 5 && !(e.target as HTMLElement).closest('.node-interactive')) {
            // Background Click
            setSelectedContainer(null);
            if (edgeMode) setEdgeSource(null);
        }
    };

    const handlePivot = async (containerId: string, targetId?: string) => {
        setPivoting(true);
        if (targetId) {
            setPivotLogs(["Initializing targeted exploit...", `Source: ${containerId}`, `Target: ${targetId}`]);
        } else {
            setPivotLogs(["Initializing pivoting attack scan...", `Source: ${containerId}`]);
        }
        setShowLogs(true);

        try {
            const res = await startPivotingAttack(containerId, targetId);
            if (res.logs && Array.isArray(res.logs)) {
                setPivotLogs(prev => [...prev, ...res.logs, "Done."]);
            } else {
                setPivotLogs(prev => [...prev, "No logs returned.", "Done."]);
            }
        } catch (err: any) {
            setPivotLogs(prev => [...prev, `Error: ${err.message}`, "Terminated."]);
        } finally {
            setPivoting(false);
            loadData(); // Refresh status to show new compromised nodes
        }
    };

    const handleLocalExploit = async (containerId: string) => {
        setAttacking(true);
        setPivotLogs(["Starting local exploit sequence...", `Target: ${containerId}`, "Executing CVE script..."]);
        setShowLogs(true);
        try {
            const res = await runLocalExploit(containerId);
            setPivotLogs(prev => [...prev, "--- Output ---", res.output || "", "--- End ---", `Status: ${res.status}`, res.message ? `Message: ${res.message}` : ""]);
            if (res.status === 'success') {
                loadData();
            }
        } catch (err: any) {
            setPivotLogs(prev => [...prev, `Error: ${err.message}`, "Terminated."]);
        } finally {
            setAttacking(false);
        }
    };

    const handleMarkCompromised = async (containerId: string) => {
        try {
            const res = await verifyCompromise(containerId);
            if (res.compromised) {
                // Success
                loadData();
            } else {
                alert(res.message || "Verification failed: Container is not compromised (/tmp/success not found).");
            }
        } catch (err: any) {
            console.error("Failed to verify compromised status", err);
            alert(`Error: ${err.message || "Verification request failed"}`);
        }
    };

    const handleViewScanResult = async (containerId: string) => {
        try {
            const res = await getPivotScanResult(containerId);
            setScanResult(res.content || "No scan result found or file is empty.");
            setShowScanResult(true);
        } catch (err: any) {
            setScanResult(`Error reading scan result: ${err.message}`);
            setShowScanResult(true);
        }
    };

    const openShell = (node: ContainerNode) => {
        setShellTarget(node);
        setShellHistory([]);
        setShellCommand('');
        setShellWorkdir('/tmp');
        setShowShell(true);
    };

    const closeShell = () => {
        setShowShell(false);
        setShellTarget(null);
        setShellHistory([]);
        setShellCommand('');
        setShellRunning(false);
    };

    const handleShellRun = async () => {
        if (!shellTarget || shellRunning) return;
        const cmd = shellCommand.trim();
        if (!cmd) return;
        setShellRunning(true);
        try {
            const res = await execInteractiveShell(shellTarget.id, cmd, shellWorkdir);
            setShellHistory(prev => [...prev, { cmd, stdout: res.stdout || '', stderr: res.stderr || '', returncode: res.returncode ?? 0 }]);
        } catch (err: any) {
            setShellHistory(prev => [...prev, { cmd, stdout: '', stderr: err.message || 'Command failed', returncode: -1 }]);
        } finally {
            setShellRunning(false);
            setShellCommand('');
        }
    };

    // --- Attack Report Handlers ---
    const openReportDialog = async () => {
        // We no longer block opening the dialog if there are no compromised nodes,
        // so the user can still check history.
        // Load saved config on first open
        if (!reportConfigLoaded) {
            try {
                const res = await fetch('/api/agent/config');
                const cfg = await res.json();
                if (cfg.status === 'success') {
                    // Don't load masked key
                    if (cfg.api_key && !cfg.api_key.includes('...') && !cfg.api_key.startsWith('***')) {
                        setReportApiKey(cfg.api_key);
                    }
                    setReportBaseUrl(cfg.base_url || '');
                    setReportModelName(cfg.model_name || '');
                }
                setReportConfigLoaded(true);
            } catch { /* ignore */ }
        }
        setShowReportDialog(true);
        if (reportDialogTab === 'history') {
            fetchReportHistory();
        }
    };

    const fetchReportHistory = async () => {
        setLoadingHistory(true);
        try {
            const history = await getAttackReportHistory();
            setReportHistoryRecords(history);
        } catch (e) {
            console.error("Failed to fetch report history", e);
        } finally {
            setLoadingHistory(false);
        }
    };

    const handleStartReport = async () => {
        if (!reportApiKey.trim()) {
            alert('API Key is required.');
            return;
        }

        const allNodes = getAllNodes();
        const hasCompromised = allNodes.some(n => n.is_compromised);
        if (!hasCompromised) {
            alert('No compromised nodes found. Please complete at least one attack first.');
            return;
        }

        setShowReportDialog(false);
        setShowReport(true);
        setReportContent('');
        setReportError('');
        setReportGenerating(true);
        setReportStatus('Initializing...');

        const abortController = new AbortController();
        reportAbortRef.current = abortController;

        const nodesPayload = allNodes.map(n => ({
            id: n.id,
            name: n.name,
            ip: n.ip,
            zone: n.zone,
            pwn_type: n.pwn_type || null,
            cve: n.cve_info?.cve || null,
            app: n.cve_info?.app || null,
        }));

        try {
            await generateAttackReport(
                nodesPayload,
                edges,
                (data) => {
                    if (data.type === 'chunk') {
                        setReportContent(prev => prev + (data.content || ''));
                    } else if (data.type === 'status') {
                        setReportStatus(data.content || '');
                    } else if (data.type === 'error') {
                        setReportError(data.content || 'Unknown error');
                    } else if (data.type === 'done') {
                        setReportGenerating(false);
                        setReportStatus('');
                    }
                },
                { api_key: reportApiKey, base_url: reportBaseUrl, model_name: reportModelName },
                abortController.signal
            );
        } catch (err: any) {
            if (err.name === 'AbortError') {
                setReportStatus('Stopped by user.');
            } else {
                setReportError(err.message || 'Failed to generate report');
            }
        } finally {
            setReportGenerating(false);
            reportAbortRef.current = null;
        }
    };

    const handleStopReport = () => {
        if (reportAbortRef.current) {
            reportAbortRef.current.abort();
            reportAbortRef.current = null;
        }
    };

    // --- Rendering Helpers ---
    const getZoneIcon = (zone: string) => {
        // Use user-provided icons from public/img/{Zone}/{Zone}_Gray.png
        switch (zone.toLowerCase()) {
            case 'external': return '/img/External/External_Gray.png';
            case 'dmz': return '/img/DMZ/DMZ_Gray.png';
            case 'intranet': return '/img/Intranet/Intranet_Gray.png';
            case 'database': return '/img/Database/Database_Gray.png';
            default: return '/img/DMZ/DMZ_Gray.png';
        }
    };

    // --- Topology Layout Constants ---
    const ZONE_HEIGHT = 300;
    const CANVAS_WIDTH = 1200;
    const CANVAS_HEIGHT = 1300; // Increased height for 4 zones

    // Visibility "Fog of War" Logic
    const isZoneVisible = (zoneName: string) => {
        if (zoneName === 'external') return true;

        const externalCompromised = data.external.some(n => n.is_compromised);
        if (zoneName === 'dmz') return externalCompromised;

        // Intranet visible if External is compromised (might be parallel entry) OR DMZ compromised
        if (zoneName === 'intranet') return externalCompromised || data.dmz.some(n => n.is_compromised);

        // Database visible if Intranet OR DMZ compromised
        if (zoneName === 'database') {
            return data.intranet.some(n => n.is_compromised) || data.dmz.some(n => n.is_compromised);
        }

        return false;
    };

    // Helper to get Position dynamically (for edges)
    const getNodePosition = (nodeId: string): { x: number, y: number } | null => {
        let foundNode = data.external.find(n => n.id === nodeId);
        let zone = 'external', list = data.external, startY = 0;

        if (!foundNode) { foundNode = data.dmz.find(n => n.id === nodeId); zone = 'dmz'; list = data.dmz; startY = 300; }
        if (!foundNode) { foundNode = data.intranet.find(n => n.id === nodeId); zone = 'intranet'; list = data.intranet; startY = 600; }
        if (!foundNode) { foundNode = data.database.find(n => n.id === nodeId); zone = 'database'; list = data.database; startY = 900; }

        if (foundNode && list && isZoneVisible(zone)) {
            const index = list.findIndex(n => n.id === nodeId);
            const spacing = CANVAS_WIDTH / (list.length + 1);
            return { x: spacing * (index + 1), y: startY + (ZONE_HEIGHT / 2) - 40 };
        }
        return null;
    };

    const getAllNodes = () => [...data.external, ...data.dmz, ...data.intranet, ...data.database];

    const getNodeById = (nodeId: string) => getAllNodes().find(n => n.id === nodeId);

    const getEdgeSeed = (edge: Edge) => {
        const seedStr = `${edge.id}-${edge.sourceId}-${edge.targetId}`;
        let hash = 0;
        for (let i = 0; i < seedStr.length; i++) {
            hash = (hash + seedStr.charCodeAt(i)) % 997;
        }
        return hash;
    };

    const getEdgeStyle = (edge: Edge) => {
        const target = getNodeById(edge.targetId);
        const source = getNodeById(edge.sourceId);
        const pwnType = target?.pwn_type || source?.pwn_type;
        if (edge.status !== 'success') {
            return {
                gradient: 'url(#edge-gradient-pending)',
                glow: 'url(#edge-glow-pending)',
                marker: 'url(#arrowhead-pending)',
                flow: '#e2e8f0',
                particle: '#94a3b8',
                accent: '#94a3b8'
            };
        }
        if (pwnType === 'SQLI') {
            return {
                gradient: 'url(#edge-gradient-sqli)',
                glow: 'url(#edge-glow-sqli)',
                marker: 'url(#arrowhead-sqli)',
                flow: '#e9d5ff',
                particle: '#c4b5fd',
                accent: '#a855f7'
            };
        }
        if (pwnType === 'FILEREAD') {
            return {
                gradient: 'url(#edge-gradient-fileread)',
                glow: 'url(#edge-glow-fileread)',
                marker: 'url(#arrowhead-fileread)',
                flow: '#fed7aa',
                particle: '#fdba74',
                accent: '#f97316'
            };
        }
        return {
            gradient: 'url(#edge-gradient-getshell)',
            glow: 'url(#edge-glow-getshell)',
            marker: 'url(#arrowhead-getshell)',
            flow: '#fecaca',
            particle: '#fda4af',
            accent: '#ef4444'
        };
    };

    const getEdgePath = (start: { x: number; y: number }, end: { x: number; y: number }, seed: number) => {
        const sx = start.x + 40;
        const sy = start.y + 50;
        const ex = end.x + 40;
        const ey = end.y + 50;
        const dx = ex - sx;
        const dy = ey - sy;
        const len = Math.hypot(dx, dy) || 1;
        const sign = seed % 2 === 0 ? 1 : -1;
        const curve = Math.min(90, Math.max(24, len * 0.12)) * (0.85 + (seed % 5) * 0.03);
        const nx = (-dy / len) * sign;
        const ny = (dx / len) * sign;
        const c1x = sx + dx * 0.25 + nx * curve;
        const c1y = sy + dy * 0.25 + ny * curve;
        const c2x = sx + dx * 0.75 + nx * curve;
        const c2y = sy + dy * 0.75 + ny * curve;
        return `M ${sx},${sy} C ${c1x},${c1y} ${c2x},${c2y} ${ex},${ey}`;
    };

    // Draw User Edges Only
    const renderEdges = () => {
        return (
            <svg className="absolute inset-0 pointer-events-none targetzone-edges" width={CANVAS_WIDTH} height={CANVAS_HEIGHT}>
                <defs>
                    <linearGradient id="edge-gradient-sqli" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#a855f7" />
                        <stop offset="50%" stopColor="#c084fc" />
                        <stop offset="100%" stopColor="#e9d5ff" />
                    </linearGradient>
                    <linearGradient id="edge-gradient-fileread" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#f97316" />
                        <stop offset="50%" stopColor="#fb923c" />
                        <stop offset="100%" stopColor="#fed7aa" />
                    </linearGradient>
                    <linearGradient id="edge-gradient-getshell" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#ef4444" />
                        <stop offset="50%" stopColor="#f97316" />
                        <stop offset="100%" stopColor="#fecaca" />
                    </linearGradient>
                    <linearGradient id="edge-gradient-pending" x1="0%" y1="0%" x2="100%" y2="0%">
                        <stop offset="0%" stopColor="#94a3b8" />
                        <stop offset="100%" stopColor="#cbd5f5" />
                    </linearGradient>
                    <filter id="edge-glow-sqli" x="-50%" y="-50%" width="200%" height="200%">
                        <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#a855f7" floodOpacity="0.5" />
                    </filter>
                    <filter id="edge-glow-fileread" x="-50%" y="-50%" width="200%" height="200%">
                        <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#f97316" floodOpacity="0.5" />
                    </filter>
                    <filter id="edge-glow-getshell" x="-50%" y="-50%" width="200%" height="200%">
                        <feDropShadow dx="0" dy="0" stdDeviation="4" floodColor="#ef4444" floodOpacity="0.5" />
                    </filter>
                    <filter id="edge-glow-pending" x="-50%" y="-50%" width="200%" height="200%">
                        <feDropShadow dx="0" dy="0" stdDeviation="3" floodColor="#94a3b8" floodOpacity="0.35" />
                    </filter>
                    <marker id="arrowhead-sqli" markerWidth="12" markerHeight="9" refX="11" refY="4.5" orient="auto" markerUnits="strokeWidth">
                        <path d="M0,0 L10,4.5 L0,9 L2,4.5 Z" fill="#a855f7" />
                    </marker>
                    <marker id="arrowhead-fileread" markerWidth="12" markerHeight="9" refX="11" refY="4.5" orient="auto" markerUnits="strokeWidth">
                        <path d="M0,0 L10,4.5 L0,9 L2,4.5 Z" fill="#f97316" />
                    </marker>
                    <marker id="arrowhead-getshell" markerWidth="12" markerHeight="9" refX="11" refY="4.5" orient="auto" markerUnits="strokeWidth">
                        <path d="M0,0 L10,4.5 L0,9 L2,4.5 Z" fill="#ef4444" />
                    </marker>
                    <marker id="arrowhead-pending" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto" markerUnits="strokeWidth">
                        <path d="M0,0 L8,3.5 L0,7 L2,3.5 Z" fill="#94a3b8" />
                    </marker>
                </defs>
                <style>{`
                    .targetzone-edges .edge-base {
                        fill: none;
                        stroke-linecap: round;
                        stroke-linejoin: round;
                    }
                    .targetzone-edges .edge-flow {
                        fill: none;
                        stroke-linecap: round;
                        stroke-linejoin: round;
                        stroke-dasharray: 8 14;
                        animation: edge-flow 1.6s linear infinite;
                    }
                    .targetzone-edges .edge-flow-success {
                        stroke-dasharray: 10 18;
                        animation-duration: 1.2s;
                    }
                    .targetzone-edges .edge-wave {
                        fill: none;
                        stroke-linecap: round;
                        stroke-linejoin: round;
                        stroke-dasharray: 6 72;
                        animation: edge-wave 2.6s ease-in-out infinite;
                    }
                    @keyframes edge-flow {
                        from { stroke-dashoffset: 26; }
                        to { stroke-dashoffset: 0; }
                    }
                    @keyframes edge-wave {
                        from { stroke-dashoffset: 120; opacity: 0.35; }
                        to { stroke-dashoffset: 0; opacity: 0; }
                    }
                `}</style>
                {edges.map(edge => {
                    const start = getNodePosition(edge.sourceId);
                    const end = getNodePosition(edge.targetId);
                    if (start && end) {
                        const seed = getEdgeSeed(edge);
                        const path = getEdgePath(start, end, seed);
                        const style = getEdgeStyle(edge);
                        const pathId = `edge-path-${edge.id}`;
                        const startX = start.x + 40;
                        const startY = start.y + 50;
                        const endX = end.x + 40;
                        const endY = end.y + 50;
                        const particleDuration = edge.status === 'success' ? 1.1 : 2.4;
                        const particleDelay = (seed % 4) * 0.2;
                        const waveDuration = edge.status === 'success' ? 3.2 : 4.8;
                        const waveDelay = (seed % 3) * 0.4;
                        return (
                            <g key={edge.id}>
                                <path id={pathId} d={path} fill="none" stroke="none" />
                                {edge.status === 'success' ? (
                                    <>
                                        <path
                                            className="edge-base"
                                            d={path}
                                            stroke={style.gradient}
                                            strokeWidth={6}
                                            opacity={0.25}
                                            filter={style.glow}
                                        />
                                        <path
                                            className="edge-base"
                                            d={path}
                                            stroke={style.gradient}
                                            strokeWidth={3.5}
                                            markerEnd={style.marker}
                                        />
                                        <path
                                            className="edge-flow edge-flow-success"
                                            d={path}
                                            stroke={style.flow}
                                            strokeWidth={2}
                                            opacity={0.85}
                                        />
                                        <path
                                            className="edge-wave"
                                            d={path}
                                            stroke={style.accent}
                                            strokeWidth={8}
                                            style={{ animationDuration: `${waveDuration}s`, animationDelay: `${waveDelay}s` }}
                                        />
                                        <circle r={3} fill={style.particle} opacity={0.9}>
                                            <animateMotion dur={`${particleDuration}s`} repeatCount="indefinite" begin={`${particleDelay}s`}>
                                                <mpath href={`#${pathId}`} />
                                            </animateMotion>
                                        </circle>
                                        <circle r={2.2} fill={style.flow} opacity={0.7}>
                                            <animateMotion dur={`${particleDuration * 1.4}s`} repeatCount="indefinite" begin={`${particleDelay + 0.5}s`}>
                                                <mpath href={`#${pathId}`} />
                                            </animateMotion>
                                        </circle>
                                        <circle cx={startX} cy={startY} r={2} fill="none" stroke={style.accent} strokeWidth={1.5} opacity={0.6}>
                                            <animate attributeName="r" values="2;12;2" dur="2.1s" repeatCount="indefinite" />
                                            <animate attributeName="opacity" values="0.55;0;0.55" dur="2.1s" repeatCount="indefinite" />
                                        </circle>
                                        <circle cx={endX} cy={endY} r={2.5} fill="#fecdd3" opacity={0.8}>
                                            <animate attributeName="r" values="2;6;2" dur="1.6s" repeatCount="indefinite" />
                                            <animate attributeName="opacity" values="0.2;0.8;0.2" dur="1.6s" repeatCount="indefinite" />
                                        </circle>
                                    </>
                                ) : (
                                    <>
                                        <path
                                            className="edge-base"
                                            d={path}
                                            stroke={style.gradient}
                                            strokeWidth={2.5}
                                            opacity={0.8}
                                            markerEnd={style.marker}
                                        />
                                        <path
                                            className="edge-flow"
                                            d={path}
                                            stroke={style.flow}
                                            strokeWidth={1.6}
                                            opacity={0.75}
                                        />
                                        <path
                                            className="edge-wave"
                                            d={path}
                                            stroke={style.accent}
                                            strokeWidth={6}
                                            style={{ animationDuration: `${waveDuration}s`, animationDelay: `${waveDelay}s` }}
                                        />
                                        <circle r={2} fill={style.particle} opacity={0.6}>
                                            <animateMotion dur={`${particleDuration}s`} repeatCount="indefinite" begin={`${particleDelay}s`}>
                                                <mpath href={`#${pathId}`} />
                                            </animateMotion>
                                        </circle>
                                        <circle cx={startX} cy={startY} r={1.5} fill="none" stroke={style.accent} strokeWidth={1} opacity={0.4}>
                                            <animate attributeName="r" values="1.5;9;1.5" dur="2.8s" repeatCount="indefinite" />
                                            <animate attributeName="opacity" values="0.35;0;0.35" dur="2.8s" repeatCount="indefinite" />
                                        </circle>
                                        <circle cx={endX} cy={endY} r={2} fill="#94a3b8" opacity={0.5}>
                                            <animate attributeName="r" values="1.5;4;1.5" dur="2.2s" repeatCount="indefinite" />
                                            <animate attributeName="opacity" values="0.1;0.5;0.1" dur="2.2s" repeatCount="indefinite" />
                                        </circle>
                                    </>
                                )}
                            </g>
                        );
                    }
                    return null;
                })}
            </svg>
        );
    };

    const renderNodes = (nodes: ContainerNode[], startY: number, zoneLabel: string) => {
        if (!isZoneVisible(zoneLabel)) return null;

        const count = nodes.length;
        const spacing = CANVAS_WIDTH / (count + 1);

        return nodes.map((node, i) => {
            const x = spacing * (i + 1);
            const y = startY + (ZONE_HEIGHT / 2) - 40;

            const cveLabel = node.cve_info?.cve ? node.cve_info.cve : null;
            const isSource = edgeSource === node.id;

            return (
                <div
                    key={node.id}
                    className={`absolute flex flex-col items-center cursor-pointer group node-interactive transition-transform ${isSource ? 'scale-110 z-20' : 'hover:scale-110'}`}
                    style={{ left: x, top: y, width: 80, height: 100 }}
                    onClick={(e) => {
                        e.stopPropagation();
                        // Edge Mode Interaction
                        if (edgeMode) {
                            if (edgeSource === null) {
                                if (node.is_compromised) {
                                    setEdgeSource(node.id);
                                } else {
                                    alert("Only compromised nodes can be the source of an attack.");
                                }
                            } else {
                                if (edgeSource === node.id) {
                                    setEdgeSource(null);
                                } else {
                                    // Handle existing edge or create new
                                    const existingEdgeIndex = edges.findIndex(ed => ed.sourceId === edgeSource && ed.targetId === node.id);

                                    if (existingEdgeIndex >= 0) {
                                        // Toggle off (Remove) if clicking again? Or just let user manage deletions separately?
                                        // User feedback "arrow cannot be cancelled" -> Let's interpret re-clicking as remove for convenience in Edge Mode
                                        setEdges(prev => prev.filter((_, idx) => idx !== existingEdgeIndex));
                                    } else {
                                        // Create pending edge
                                        // Allowed multiple parents (many-to-one) as requested
                                        setEdges(prev => [...prev, {
                                            id: `edge-${Date.now()}`,
                                            sourceId: edgeSource!,
                                            targetId: node.id,
                                            status: 'pending'
                                        }]);
                                    }
                                    setEdgeSource(null);
                                }
                            }
                            return;
                        }

                        // Normal Mode Interaction
                        if (selectedContainer?.id === node.id) {
                            setSelectedContainer(null);
                        } else {
                            setSelectedContainer({ ...node, zone: zoneLabel });
                        }
                    }}
                >
                    {/* Icon */}
                    <div className={`w-16 h-16 bg-transparent flex items-center justify-center relative transition-transform duration-200 ${node.is_compromised
                        ? (node.pwn_type === 'SQLI'
                            ? 'drop-shadow-[0_0_10px_rgba(147,51,234,0.8)]'
                            : node.pwn_type === 'FILEREAD'
                                ? 'drop-shadow-[0_0_10px_rgba(249,115,22,0.8)]'
                                : 'drop-shadow-[0_0_10px_rgba(239,68,68,0.8)]')
                        : ''
                        } ${isSource ? 'ring-4 ring-blue-500 rounded-full' : ''}`}>
                        {/* Use zone-specific Gray icon */}
                        <img
                            src={getZoneIcon(zoneLabel)}
                            alt={node.name}
                            onError={(e) => {
                                (e.target as HTMLImageElement).style.display = 'none';
                                (e.target as HTMLImageElement).nextElementSibling?.classList.remove('hidden');
                            }}
                            className="w-full h-full object-contain drop-shadow-md"
                        />
                        {/* Fallback Icon */}
                        <div className="hidden absolute inset-0 flex items-center justify-center bg-slate-200 dark:bg-slate-700 text-slate-400 dark:text-slate-300 rounded-full">
                            <span className="font-bold text-xs uppercase">{node.name.slice(0, 3)}</span>
                        </div>

                        {/* Compromised Badge */}
                        {node.is_compromised && (
                            <div className={`absolute -top-2 -right-2 text-white rounded-full p-1 shadow-lg animate-pulse ${node.pwn_type === 'SQLI'
                                ? 'bg-purple-600'
                                : node.pwn_type === 'FILEREAD'
                                    ? 'bg-orange-500'
                                    : 'bg-red-600'
                                }`} title={node.pwn_type === 'SQLI' ? 'SQLI Success' : 'Compromised'}>
                                <Skull className="w-4 h-4" />
                            </div>
                        )}
                    </div>
                    {/* Label */}
                    <span className={`mt-2 text-xs font-medium px-2 py-0.5 rounded shadow-sm border truncate max-w-full ${node.is_compromised
                        ? (node.pwn_type === 'SQLI'
                            ? 'bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-900/30 dark:text-purple-300 dark:border-purple-800'
                            : (node.pwn_type === 'FILEREAD'
                                ? 'bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-900/30 dark:text-orange-300 dark:border-orange-800'
                                : 'bg-red-50 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-300 dark:border-red-800'))
                        : 'text-slate-600 dark:text-slate-300 bg-white/80 dark:bg-slate-800/80 border-slate-200 dark:border-slate-700'
                        }`}>
                        {cveLabel || node.name}
                    </span>

                    {/* Popup Details (Sticky) */}
                    {selectedContainer?.id === node.id && (
                        <div className="absolute left-full top-0 ml-4 w-72 bg-white dark:bg-slate-800 rounded-xl shadow-xl border border-slate-200 dark:border-slate-700 z-50 p-4 animate-in fade-in slide-in-from-left-4 duration-200 text-left">
                            <div className="flex justify-between items-start mb-2">
                                <h3 className="font-bold text-slate-800 dark:text-slate-200 text-sm flex items-center gap-2">
                                    {node.name}
                                    {node.is_compromised && (
                                        <div className={`flex items-center gap-1.5 text-[10px] px-2 py-0.5 rounded-md font-semibold border shadow-sm tracking-tight ${node.pwn_type === 'SQLI'
                                            ? 'bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-900/40 dark:text-purple-300 dark:border-purple-700/50'
                                            : (node.pwn_type === 'FILEREAD'
                                                ? 'bg-orange-50 text-orange-700 border-orange-200 dark:bg-orange-900/40 dark:text-orange-300 dark:border-orange-700/50'
                                                : 'bg-red-50 text-red-700 border-red-200 dark:bg-red-900/40 dark:text-red-300 dark:border-red-700/50')
                                            }`}>
                                            {node.pwn_type === 'SQLI' ? <Database className="w-3 h-3" /> : (node.pwn_type === 'FILEREAD' ? <FileSearch className="w-3 h-3" /> : <Skull className="w-3 h-3" />)}
                                            {node.pwn_type === 'SQLI' ? 'SQL Injection' : (node.pwn_type === 'FILEREAD' ? 'File Read' : 'GetShell')}
                                        </div>
                                    )}
                                </h3>
                                <button onClick={(e) => { e.stopPropagation(); setSelectedContainer(null); }} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
                                    <X className="w-4 h-4" />
                                </button>
                            </div>
                            <div className="space-y-2 text-xs text-slate-600 dark:text-slate-400 mb-4">
                                <div className="flex items-center gap-2">
                                    <span className="font-semibold w-12 shrink-0">ID:</span>
                                    <span className="font-mono bg-slate-100 dark:bg-slate-900 px-1 rounded">{node.id.slice(0, 12)}</span>
                                </div>
                                <div className="flex items-start gap-2">
                                    <span className="font-semibold w-12 shrink-0 mt-0.5">IP:</span>
                                    <div className="flex flex-col gap-1">
                                        {node.ip ? node.ip.split(',').map((ip, i) => (
                                            <span key={i} className="font-mono bg-slate-100 dark:bg-slate-900 px-1 rounded text-blue-600 dark:text-blue-400 block">
                                                {ip.trim()}
                                            </span>
                                        )) : <span className="font-mono bg-slate-100 dark:bg-slate-900 px-1 rounded text-gray-400">N/A</span>}
                                    </div>
                                </div>
                                {node.cve_info?.cve && (
                                    <div className="flex items-center gap-2">
                                        <span className="font-semibold w-12 shrink-0">CVE:</span>
                                        <span className="font-mono bg-yellow-100 dark:bg-yellow-900/30 text-yellow-700 dark:text-yellow-400 px-1 rounded">{node.cve_info.cve}</span>
                                    </div>
                                )}
                            </div>

                            {/* Actions */}
                            {node.is_compromised ? (
                                <div className="space-y-2">
                                    {node.pwn_type === 'FILEREAD' && (
                                        <FileReadPanel containerId={node.id} />
                                    )}
                                    {node.pwn_type !== 'SQLI' && node.pwn_type !== 'FILEREAD' && (
                                        <>
                                            {node.pwn_type === 'RCE' && (
                                                <button
                                                    onClick={(e) => { e.stopPropagation(); openShell(node); }}
                                                    className="w-full flex items-center justify-center gap-2 bg-slate-900 hover:bg-black text-emerald-300 py-2 rounded-lg font-medium text-xs transition-colors border border-emerald-500/30 shadow-md"
                                                >
                                                    <Terminal className="w-3 h-3" />
                                                    Interactive Shell
                                                </button>
                                            )}
                                            <button
                                                onClick={(e) => { e.stopPropagation(); handlePivot(node.id); }}
                                                disabled={pivoting}
                                                className="w-full flex items-center justify-center gap-2 bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg font-medium text-xs transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-md"
                                            >
                                                {pivoting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Play className="w-3 h-3 fill-current" />}
                                                Start Pivot Attack
                                            </button>

                                            <button
                                                onClick={(e) => { e.stopPropagation(); handleViewScanResult(node.id); }}
                                                className="w-full flex items-center justify-center gap-2 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300 py-2 rounded-lg font-medium text-xs transition-colors border border-slate-200 dark:border-slate-600"
                                            >
                                                <FileText className="w-3 h-3" />
                                                View Scan Result
                                            </button>
                                        </>
                                    )}
                                </div>
                            ) : (
                                <div className="space-y-2">
                                    {edges.find(e => e.targetId === node.id) ? (
                                        <>
                                            <button
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    const sourceId = edges.find(e => e.targetId === node.id)?.sourceId;
                                                    if (sourceId) handlePivot(sourceId, node.id);
                                                }}
                                                disabled={pivoting}
                                                className="w-full flex items-center justify-center gap-2 bg-red-600 hover:bg-red-700 text-white py-2 rounded-lg font-medium text-xs transition-colors shadow-md disabled:opacity-50"
                                            >
                                                {pivoting ? <Loader2 className="w-3 h-3 animate-spin" /> : <Skull className="w-3 h-3 fill-current" />}
                                                Exploit from Source
                                            </button>
                                            <button
                                                onClick={(e) => {
                                                    e.stopPropagation();
                                                    const edgeToRemove = edges.find(e => e.targetId === node.id);
                                                    if (edgeToRemove) {
                                                        setEdges(prev => prev.filter(edge => edge.id !== edgeToRemove.id));
                                                        setSelectedContainer(null); // Close popup
                                                    }
                                                }}
                                                className="w-full flex items-center justify-center gap-2 bg-slate-100 hover:bg-slate-200 dark:bg-slate-700 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300 py-2 rounded-lg font-medium text-xs transition-colors border border-slate-200 dark:border-slate-600"
                                            >
                                                <Trash2 className="w-3 h-3" />
                                                Disconnect Link
                                            </button>
                                        </>
                                    ) : (
                                        <div className="text-[10px] text-center text-slate-400 italic">
                                            {/* Logic for initial connection state hint */}
                                            {node.zone.toLowerCase() !== 'external' ? 'Connect a compromised node to attack' : 'External Target Ready'}
                                        </div>
                                    )}

                                    {/* Local Attack Button for External/Unconnected Nodes */}
                                    {!node.is_compromised && node.zone.toLowerCase() === 'external' && !edges.find(e => e.targetId === node.id) && (
                                        <button
                                            onClick={(e) => { e.stopPropagation(); handleLocalExploit(node.id); }}
                                            disabled={attacking}
                                            className="w-full flex items-center justify-center gap-2 bg-orange-600 hover:bg-orange-700 text-white py-2 rounded-lg font-medium text-xs transition-colors shadow-md disabled:opacity-50 mt-2"
                                        >
                                            {attacking ? <Loader2 className="w-3 h-3 animate-spin" /> : <Zap className="w-3 h-3 fill-current" />}
                                            Attack (Local Script)
                                        </button>
                                    )}

                                    <button
                                        onClick={(e) => { e.stopPropagation(); handleMarkCompromised(node.id); }}
                                        className="w-full flex items-center justify-center gap-2 bg-slate-100 dark:bg-slate-700 hover:bg-slate-200 dark:hover:bg-slate-600 text-slate-600 dark:text-slate-300 py-1.5 rounded-lg font-medium text-[10px] transition-colors border border-slate-200 dark:border-slate-600 mt-2"
                                    >
                                        <ShieldAlert className="w-3 h-3" />
                                        Verify Pwned Status
                                    </button>
                                </div>
                            )}
                        </div>
                    )}
                </div>
            );
        });
    };

    return (
        <div className="h-screen flex flex-col bg-slate-50 dark:bg-slate-900 overflow-hidden">
            {/* Header Toolbar */}
            <div className="absolute top-20 right-8 z-10 flex flex-col gap-2 bg-white/90 dark:bg-slate-800/90 backdrop-blur p-2 rounded-lg shadow-lg border border-slate-200 dark:border-slate-700">
                <button onClick={() => setScale(s => Math.min(s + 0.1, 3))} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded text-slate-600 dark:text-slate-300" title="Zoom In">
                    <ZoomIn className="w-5 h-5" />
                </button>
                <button onClick={() => setScale(s => Math.max(s - 0.1, 0.5))} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded text-slate-600 dark:text-slate-300" title="Zoom Out">
                    <ZoomOut className="w-5 h-5" />
                </button>
                <button onClick={() => { setScale(1); setOffset({ x: 0, y: 0 }); }} className="p-2 hover:bg-slate-100 dark:hover:bg-slate-700 rounded text-slate-600 dark:text-slate-300" title="Reset">
                    <Move className="w-5 h-5" />
                </button>
                <div className="h-px bg-slate-200 dark:bg-slate-700 my-1"></div>
                <button
                    onClick={() => { setEdgeMode(!edgeMode); setEdgeSource(null); }}
                    className={`p-2 rounded transition-colors ${edgeMode ? 'bg-blue-100 text-blue-600 dark:bg-blue-900/50 dark:text-blue-400 ring-2 ring-blue-500' : 'hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300'}`}
                    title={edgeMode ? "Exit Connection Mode" : "Enter Connection Mode"}
                >
                    <Network className="w-5 h-5" />
                </button>
                <div className="h-px bg-slate-200 dark:bg-slate-700 my-1"></div>
                <button onClick={loadData} className="p-2 hover:bg-blue-50 dark:hover:bg-blue-900/20 rounded text-blue-600 dark:text-blue-400 font-bold text-xs" title="Refresh">
                    REFRESH
                </button>
                <div className="h-px bg-slate-200 dark:bg-slate-700 my-1"></div>
                <button
                    onClick={openReportDialog}
                    disabled={reportGenerating}
                    className={`p-2 rounded transition-colors ${reportGenerating
                        ? 'bg-amber-100 dark:bg-amber-900/30 text-amber-500 cursor-wait'
                        : 'hover:bg-amber-50 dark:hover:bg-amber-900/20 text-amber-600 dark:text-amber-400'
                        }`}
                    title="Generate Attack Report"
                >
                    {reportGenerating ? <Loader2 className="w-5 h-5 animate-spin" /> : <ScrollText className="w-5 h-5" />}
                </button>
            </div>

            {/* Canvas Area */}
            <div
                ref={containerRef}
                className="flex-1 overflow-hidden relative cursor-grab active:cursor-grabbing"
                onWheel={handleWheel}
                onMouseDown={handleMouseDown}
                onMouseMove={handleMouseMove}
                onMouseUp={handleMouseUp}
                onMouseLeave={handleMouseUp}
            >
                <div
                    className="absolute origin-top-left transition-transform duration-75 ease-out"
                    style={{
                        transform: `translate(${offset.x}px, ${offset.y}px) scale(${scale})`,
                        width: CANVAS_WIDTH,
                        height: CANVAS_HEIGHT
                    }}
                >
                    {/* Background Zones */}
                    <div className="absolute inset-0 border-2 border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-950 shadow-2xl rounded-xl overflow-hidden">
                        {/* Zone 0: External - The Internet / Public Access */}
                        <div className="h-[300px] w-full border-b-2 border-slate-300 dark:border-slate-700 relative bg-gradient-to-b from-slate-100 via-transparent to-transparent dark:from-slate-800/30">
                            <div className="absolute left-0 top-0 bottom-0 w-12 bg-slate-100 dark:bg-slate-800 flex items-center justify-center border-r border-slate-200 dark:border-slate-700">
                                <span className="-rotate-90 whitespace-nowrap font-bold text-slate-400 dark:text-slate-500 tracking-widest text-sm">EXTERNAL</span>
                            </div>
                        </div>

                        {/* Zone 1: DMZ */}
                        <div className="h-[300px] w-full border-b-2 border-slate-300 dark:border-slate-700 relative bg-gradient-to-b from-blue-50/50 via-transparent to-transparent dark:from-blue-900/10">
                            <div className="absolute left-0 top-0 bottom-0 w-12 bg-slate-100 dark:bg-slate-800 flex items-center justify-center border-r border-slate-200 dark:border-slate-700">
                                <span className="-rotate-90 whitespace-nowrap font-bold text-slate-400 dark:text-slate-500 tracking-widest text-sm">DMZ ZONE</span>
                            </div>
                        </div>
                        {/* Zone 2: Intranet */}
                        <div className="h-[300px] w-full border-b-2 border-slate-300 dark:border-slate-700 relative bg-gradient-to-b from-purple-50/50 via-transparent to-transparent dark:from-purple-900/10">
                            <div className="absolute left-0 top-0 bottom-0 w-12 bg-slate-100 dark:bg-slate-800 flex items-center justify-center border-r border-slate-200 dark:border-slate-700">
                                <span className="-rotate-90 whitespace-nowrap font-bold text-slate-400 dark:text-slate-500 tracking-widest text-sm">INTRANET</span>
                            </div>
                        </div>
                        {/* Zone 3: Database */}
                        <div className="h-[300px] w-full relative bg-gradient-to-b from-orange-50/50 via-transparent to-transparent dark:from-orange-900/10">
                            <div className="absolute left-0 top-0 bottom-0 w-12 bg-slate-100 dark:bg-slate-800 flex items-center justify-center border-r border-slate-200 dark:border-slate-700">
                                <span className="-rotate-90 whitespace-nowrap font-bold text-slate-400 dark:text-slate-500 tracking-widest text-sm">DATABASE</span>
                            </div>
                        </div>
                    </div>

                    {/* Connections */}
                    {renderEdges()}

                    {/* Nodes - Rendered last to be on top */}
                    {renderNodes(data.external, 0, 'external')}
                    {renderNodes(data.dmz, 300, 'dmz')}
                    {renderNodes(data.intranet, 600, 'intranet')}
                    {renderNodes(data.database, 900, 'database')}
                </div>
            </div>

            {/* Log Terminal Panel */}
            {showLogs && (
                <div className="absolute bottom-12 left-8 right-8 z-30 bg-slate-900 text-slate-200 rounded-lg shadow-2xl border border-slate-700 flex flex-col max-h-[300px] animate-in slide-in-from-bottom-5">
                    <div className="flex items-center justify-between px-4 py-2 bg-slate-800 border-b border-slate-700 rounded-t-lg">
                        <div className="flex items-center gap-2 text-xs font-mono">
                            <Terminal className="w-4 h-4 text-green-400" />
                            <span>Pivoting Attack Logs</span>
                            {pivoting && <Loader2 className="w-3 h-3 animate-spin text-slate-400" />}
                        </div>
                        <button onClick={() => setShowLogs(false)} className="text-slate-400 hover:text-white">
                            <X className="w-4 h-4" />
                        </button>
                    </div>
                    <div className="p-4 overflow-y-auto font-mono text-xs space-y-1 scrollbar-thin scrollbar-thumb-slate-700 scrollbar-track-transparent">
                        {pivotLogs.length === 0 ? (
                            <span className="text-slate-500 italic">Waiting for logs...</span>
                        ) : (
                            pivotLogs.map((log, i) => (
                                <div key={i} className="break-all whitespace-pre-wrap">
                                    <span className="text-green-500 mr-2">$</span>
                                    {log}
                                </div>
                            ))
                        )}
                        {/* Auto scroll anchor */}
                        <div ref={(el) => { el?.scrollIntoView({ behavior: "smooth" }) }} />
                    </div>
                </div>
            )}

            {/* Scan Result Modal */}
            {showScanResult && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm p-8" onClick={() => setShowScanResult(false)}>
                    <div className="bg-white dark:bg-slate-900 w-full max-w-4xl max-h-[80vh] rounded-xl shadow-2xl border border-slate-200 dark:border-slate-700 flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
                        <div className="flex justify-between items-center p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50">
                            <h3 className="font-bold text-slate-700 dark:text-slate-200 flex items-center gap-2">
                                <FileText className="w-4 h-4" />
                                /tmp/result.txt Content
                            </h3>
                            <button onClick={() => setShowScanResult(false)} className="p-1 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors">
                                <X className="w-5 h-5 text-slate-500" />
                            </button>
                        </div>
                        <div className="flex-1 overflow-auto p-4 bg-slate-950">
                            <pre className="font-mono text-xs text-green-400 whitespace-pre-wrap">{scanResult}</pre>
                        </div>
                    </div>
                </div>
            )}

            {/* Interactive Shell Modal (RCE only) */}
            {showShell && shellTarget && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-6" onClick={closeShell}>
                    <div className="bg-white dark:bg-slate-900 w-full max-w-5xl max-h-[85vh] rounded-xl shadow-2xl border border-slate-200 dark:border-slate-700 flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-slate-800/50">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-emerald-100 dark:bg-emerald-900/30 rounded-lg text-emerald-600 dark:text-emerald-400">
                                    <Terminal className="w-4 h-4" />
                                </div>
                                <div>
                                    <div className="font-semibold text-slate-800 dark:text-slate-100">Interactive Shell</div>
                                    <div className="text-xs text-slate-500 dark:text-slate-400 font-mono">
                                        {shellTarget.name} · {shellTarget.id.slice(0, 12)} · {shellTarget.zone.toUpperCase()}
                                    </div>
                                </div>
                            </div>
                            <button onClick={closeShell} className="p-1 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors">
                                <X className="w-5 h-5 text-slate-500" />
                            </button>
                        </div>

                        <div className="flex flex-col gap-3 p-4 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900">
                            <div className="flex items-center gap-2 text-xs text-slate-600 dark:text-slate-400">
                                <span className="font-semibold">Workdir</span>
                                <input
                                    value={shellWorkdir}
                                    onChange={(e) => setShellWorkdir(e.target.value)}
                                    className="flex-1 bg-slate-50 dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded px-2 py-1 text-slate-700 dark:text-slate-200 font-mono text-xs"
                                    placeholder="/tmp"
                                />
                                <span className="text-[10px] text-slate-400">Use `cd` in command for one-off paths</span>
                            </div>
                            <div className="flex gap-2">
                                <input
                                    value={shellCommand}
                                    onChange={(e) => setShellCommand(e.target.value)}
                                    onKeyDown={(e) => {
                                        if (e.key === 'Enter' && !e.shiftKey) {
                                            e.preventDefault();
                                            handleShellRun();
                                        }
                                    }}
                                    className="flex-1 bg-white dark:bg-slate-800 border border-slate-300 dark:border-slate-700 rounded px-3 py-2 text-slate-800 dark:text-slate-200 font-mono text-sm"
                                    placeholder="whoami"
                                />
                                <button
                                    onClick={handleShellRun}
                                    disabled={shellRunning || !shellCommand.trim()}
                                    className="px-4 py-2 bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg text-sm font-medium flex items-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed"
                                >
                                    {shellRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                                    Run
                                </button>
                            </div>
                        </div>

                        <div className="flex-1 overflow-auto bg-slate-950 text-slate-200 font-mono text-xs p-4">
                            {shellHistory.length === 0 ? (
                                <div className="text-slate-500 italic">Run a command to start the session.</div>
                            ) : (
                                shellHistory.map((entry, idx) => (
                                    <div key={`${entry.cmd}-${idx}`} className="mb-4">
                                        <div className="text-emerald-400">$ {entry.cmd}</div>
                                        {entry.stdout && (
                                            <pre className="whitespace-pre-wrap break-all text-slate-200 mt-1">{entry.stdout}</pre>
                                        )}
                                        {entry.stderr && (
                                            <pre className="whitespace-pre-wrap break-all text-red-400 mt-1">{entry.stderr}</pre>
                                        )}
                                        <div className="text-[10px] text-slate-500 mt-1">exit {entry.returncode}</div>
                                    </div>
                                ))
                            )}
                            <div ref={shellBottomRef} />
                        </div>
                    </div>
                </div>
            )}

            {/* Report Config Dialog */}
            {showReportDialog && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/50 backdrop-blur-sm p-8" onClick={() => setShowReportDialog(false)}>
                    <div className="bg-white dark:bg-slate-900 w-full max-w-md max-h-[80vh] rounded-xl shadow-2xl border border-slate-200 dark:border-slate-700 flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
                        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-800 bg-gradient-to-r from-amber-50 to-orange-50 dark:from-amber-900/20 dark:to-orange-900/20 shrink-0">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-amber-100 dark:bg-amber-900/40 rounded-lg text-amber-600 dark:text-amber-400">
                                    <ScrollText className="w-5 h-5" />
                                </div>
                                <div className="font-semibold text-slate-800 dark:text-slate-100">Attack Report</div>
                            </div>
                            <button onClick={() => setShowReportDialog(false)} className="p-1 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors">
                                <X className="w-5 h-5 text-slate-500" />
                            </button>
                        </div>

                        {/* Tabs */}
                        <div className="flex border-b border-slate-200 dark:border-slate-800 shrink-0">
                            <button
                                className={`flex-1 py-3 text-sm font-medium transition-colors ${reportDialogTab === 'new' ? 'text-amber-600 dark:text-amber-400 border-b-2 border-amber-500' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-amber-400'}`}
                                onClick={() => setReportDialogTab('new')}
                            >
                                Generate New
                            </button>
                            <button
                                className={`flex-1 flex items-center justify-center gap-2 py-3 text-sm font-medium transition-colors ${reportDialogTab === 'history' ? 'text-amber-600 dark:text-amber-400 border-b-2 border-amber-500' : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-amber-400'}`}
                                onClick={() => { setReportDialogTab('history'); fetchReportHistory(); }}
                            >
                                <Clock className="w-4 h-4" />
                                History
                            </button>
                        </div>

                        {/* Content Area */}
                        <div className="flex-1 overflow-y-auto">
                            {reportDialogTab === 'new' ? (
                                <div className="p-5 space-y-4">
                                    <div>
                                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                                            <KeyRound className="w-3 h-3" /> API Key <span className="text-red-400">*</span>
                                        </label>
                                        <input
                                            type="password"
                                            value={reportApiKey}
                                            onChange={e => setReportApiKey(e.target.value)}
                                            placeholder="sk-..."
                                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-800 dark:text-slate-200 focus:ring-2 focus:ring-amber-500 focus:border-amber-500"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                                            <Globe className="w-3 h-3" /> Base URL
                                        </label>
                                        <input
                                            type="text"
                                            value={reportBaseUrl}
                                            onChange={e => setReportBaseUrl(e.target.value)}
                                            placeholder="https://api.moonshot.cn/v1"
                                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-800 dark:text-slate-200 focus:ring-2 focus:ring-amber-500 focus:border-amber-500"
                                        />
                                    </div>
                                    <div>
                                        <label className="block text-xs font-medium text-slate-600 dark:text-slate-400 mb-1 flex items-center gap-1">
                                            <HardDrive className="w-3 h-3" /> Model Name
                                        </label>
                                        <input
                                            type="text"
                                            value={reportModelName}
                                            onChange={e => setReportModelName(e.target.value)}
                                            placeholder="moonshot-v1-8k"
                                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-700 rounded-lg text-sm text-slate-800 dark:text-slate-200 focus:ring-2 focus:ring-amber-500 focus:border-amber-500"
                                        />
                                    </div>
                                    <button
                                        onClick={handleStartReport}
                                        className="w-full py-2.5 mt-2 bg-amber-600 hover:bg-amber-500 text-white rounded-lg text-sm font-semibold flex items-center justify-center gap-2 shadow-md hover:shadow-lg transition-all"
                                    >
                                        <Play className="w-4 h-4" />
                                        Start Analysis
                                    </button>
                                </div>
                            ) : (
                                <div className="p-4 space-y-3 min-h-[300px]">
                                    {loadingHistory ? (
                                        <div className="flex items-center justify-center h-full text-slate-500 py-12">
                                            <Loader2 className="w-6 h-6 animate-spin" />
                                        </div>
                                    ) : reportHistoryRecords.length === 0 ? (
                                        <div className="text-center py-12 text-slate-500 dark:text-slate-400 text-sm">
                                            No report history found.
                                        </div>
                                    ) : (
                                        reportHistoryRecords.map((record, idx) => (
                                            <div
                                                key={idx}
                                                onClick={async () => {
                                                    try {
                                                        const content = await getAttackReportContent(record.filename);
                                                        setShowReportDialog(false);
                                                        setShowReport(true);
                                                        setReportContent(content);
                                                        setReportError('');
                                                        setReportGenerating(false);
                                                    } catch (e: any) {
                                                        alert("Failed to load report: " + e.message);
                                                    }
                                                }}
                                                className="bg-slate-50 dark:bg-slate-950 border border-slate-200 dark:border-slate-800 rounded-lg p-3 cursor-pointer hover:border-amber-500/50 hover:shadow-md transition-all group"
                                            >
                                                <div className="font-medium text-slate-800 dark:text-slate-200 group-hover:text-amber-600 dark:group-hover:text-amber-400 transition-colors text-sm break-all">
                                                    {record.filename}
                                                </div>
                                                <div className="flex items-center justify-between mt-2">
                                                    <div className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400">
                                                        <Calendar className="w-3.5 h-3.5" />
                                                        <span>{new Date(record.created_at * 1000).toLocaleString()}</span>
                                                    </div>
                                                    <div className="text-xs text-slate-400 dark:text-slate-500 font-mono">
                                                        {(record.size_bytes / 1024).toFixed(1)} KB
                                                    </div>
                                                </div>
                                            </div>
                                        ))
                                    )}
                                </div>
                            )}
                        </div>
                    </div>
                </div>
            )}

            {/* Attack Report Modal */}
            {showReport && (
                <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-6" onClick={() => !reportGenerating && setShowReport(false)}>
                    <div className="bg-white dark:bg-slate-900 w-full max-w-5xl max-h-[90vh] rounded-xl shadow-2xl border border-slate-200 dark:border-slate-700 flex flex-col overflow-hidden" onClick={e => e.stopPropagation()}>
                        {/* Header */}
                        <div className="flex items-center justify-between p-4 border-b border-slate-200 dark:border-slate-800 bg-gradient-to-r from-amber-50 to-orange-50 dark:from-amber-900/20 dark:to-orange-900/20">
                            <div className="flex items-center gap-3">
                                <div className="p-2 bg-amber-100 dark:bg-amber-900/40 rounded-lg text-amber-600 dark:text-amber-400">
                                    <ScrollText className="w-5 h-5" />
                                </div>
                                <div>
                                    <div className="font-semibold text-slate-800 dark:text-slate-100">Attack Chain Report</div>
                                    <div className="text-xs text-slate-500 dark:text-slate-400">
                                        {reportGenerating ? (
                                            <span className="flex items-center gap-1.5">
                                                <Loader2 className="w-3 h-3 animate-spin" />
                                                {reportStatus || 'Generating...'}
                                            </span>
                                        ) : reportError ? (
                                            <span className="text-red-500">{reportError}</span>
                                        ) : reportContent ? (
                                            'Report generated successfully'
                                        ) : (
                                            'Stopped'
                                        )}
                                    </div>
                                </div>
                            </div>
                            <div className="flex items-center gap-2">
                                {reportGenerating && (
                                    <button
                                        onClick={handleStopReport}
                                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-red-100 hover:bg-red-200 dark:bg-red-900/30 dark:hover:bg-red-900/50 text-red-600 dark:text-red-400 rounded-lg transition-colors"
                                        title="Stop Generation"
                                    >
                                        <Square className="w-3.5 h-3.5 fill-current" />
                                        Stop
                                    </button>
                                )}
                                {reportContent && !reportGenerating && (
                                    <button
                                        onClick={() => { navigator.clipboard.writeText(reportContent); }}
                                        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-slate-100 hover:bg-slate-200 dark:bg-slate-800 dark:hover:bg-slate-700 text-slate-600 dark:text-slate-300 rounded-lg transition-colors"
                                        title="Copy Report"
                                    >
                                        <ClipboardCopy className="w-3.5 h-3.5" />
                                        Copy
                                    </button>
                                )}
                                <button onClick={() => { if (!reportGenerating) setShowReport(false); }} className="p-1 hover:bg-slate-200 dark:hover:bg-slate-700 rounded-lg transition-colors">
                                    <X className="w-5 h-5 text-slate-500" />
                                </button>
                            </div>
                        </div>
                        {/* Report Body */}
                        <div className="flex-1 overflow-auto p-6 bg-white dark:bg-slate-950">
                            {reportError && !reportContent ? (
                                <div className="flex flex-col items-center justify-center h-full text-center">
                                    <ShieldAlert className="w-12 h-12 text-red-400 mb-3" />
                                    <p className="text-red-500 font-medium">{reportError}</p>
                                </div>
                            ) : !reportContent && reportGenerating ? (
                                <div className="flex flex-col items-center justify-center h-64 text-center">
                                    <Loader2 className="w-10 h-10 text-amber-500 animate-spin mb-4" />
                                    <p className="text-slate-500 dark:text-slate-400 text-sm">{reportStatus || 'Preparing report...'}</p>
                                </div>
                            ) : (
                                <div className="prose prose-slate dark:prose-invert prose-sm max-w-none
                                    prose-headings:text-slate-800 dark:prose-headings:text-slate-200
                                    prose-h2:border-b prose-h2:border-slate-200 dark:prose-h2:border-slate-700 prose-h2:pb-2 prose-h2:mt-8
                                    prose-table:border-collapse prose-th:bg-slate-100 dark:prose-th:bg-slate-800 prose-th:px-3 prose-th:py-2 prose-th:text-left prose-th:border prose-th:border-slate-300 dark:prose-th:border-slate-600
                                    prose-td:px-3 prose-td:py-2 prose-td:border prose-td:border-slate-200 dark:prose-td:border-slate-700
                                    prose-code:bg-slate-100 dark:prose-code:bg-slate-800 prose-code:px-1.5 prose-code:py-0.5 prose-code:rounded prose-code:text-xs
                                    prose-pre:bg-slate-900 prose-pre:text-slate-200 prose-pre:rounded-lg
                                    break-words"
                                >
                                    <ReactMarkdown
                                        remarkPlugins={[remarkGfm]}
                                        components={{
                                            code({ node, inline, className, children, ...props }: any) {
                                                const match = /language-(\w+)/.exec(className || '');
                                                if (!inline) {
                                                    if (match && match[1] === 'mermaid') {
                                                        return <MermaidDiagram chart={String(children).replace(/\n$/, '')} />;
                                                    }
                                                    if (match) {
                                                        return (
                                                            <div className="not-prose my-4">
                                                                <SyntaxHighlighter
                                                                    {...props}
                                                                    style={vscDarkPlus as any}
                                                                    language={match[1]}
                                                                    PreTag="div"
                                                                    showLineNumbers={false}
                                                                    wrapLongLines={true}
                                                                    customStyle={{
                                                                        margin: 0,
                                                                        borderRadius: '0.5rem',
                                                                        fontSize: '0.8rem',
                                                                        padding: '1rem'
                                                                    }}
                                                                >
                                                                    {String(children).replace(/\n$/, '')}
                                                                </SyntaxHighlighter>
                                                            </div>
                                                        );
                                                    }
                                                    // Fallback for code blocks without a language
                                                    return (
                                                        <div className="not-prose my-4 p-4 bg-slate-900 rounded-lg overflow-x-auto shadow-inner">
                                                            <pre className="text-sm font-mono text-slate-300 bg-transparent m-0 p-0">
                                                                <code className="bg-transparent text-inherit bg-none p-0 border-none">{String(children).replace(/\n$/, '')}</code>
                                                            </pre>
                                                        </div>
                                                    );
                                                }
                                                // Inline code
                                                return (
                                                    <code {...props} className={`${className || ''} bg-slate-100 dark:bg-slate-800 text-purple-600 dark:text-purple-400 px-1 py-0.5 rounded text-xs font-mono`}>
                                                        {children}
                                                    </code>
                                                );
                                            }
                                        }}
                                    >
                                        {reportContent}
                                    </ReactMarkdown>
                                </div>
                            )}
                            <div ref={reportBottomRef} />
                        </div>
                    </div>
                </div>
            )}

            {/* Legend / Status Bar */}
            <div className="bg-white dark:bg-slate-800 border-t border-slate-200 dark:border-slate-700 px-6 py-2 text-xs text-slate-500 dark:text-slate-400 flex justify-between items-center z-20">
                <div className="flex gap-4">
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-100 dark:bg-blue-900 border border-blue-300 dark:border-blue-700"></span> DMZ Zone</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-purple-100 dark:bg-purple-900 border border-purple-300 dark:border-purple-700"></span> Intranet</span>
                    <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-100 dark:bg-orange-900 border border-orange-300 dark:border-orange-700"></span> Database Zone</span>
                </div>
                <div>
                    {loading ? 'Refreshing...' : `Last Updated: ${new Date().toLocaleTimeString()}`}
                </div>
            </div>
        </div>
    );
}
