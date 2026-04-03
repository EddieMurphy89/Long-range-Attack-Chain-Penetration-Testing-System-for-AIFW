// ── Type Definitions ──────────────────────────────────────────
const API_BASE = "/api"; // Proxied to backend

export interface Zone {
    id: string;
    name: string;
    zone: string;
    status: string;
    ports: string[];
    ip: string;
    is_compromised: boolean;
    pwn_type?: string;
    cve_info: { app?: string; cve?: string };
}

export interface ZoneMap {
    external: Zone[];
    dmz: Zone[];
    intranet: Zone[];
    database: Zone[];
    aifw: Zone[];
}

export interface AIFWStatus {
    running: boolean;
    container_status: string;
    enabled: boolean;
    dmz_ip?: string;
    internal_ip?: string;
    intercept_rules?: string[];
    mode?: string;
}

export interface InterceptRule {
    target: string;
    local_port: number;
}

export interface VulnInfo {
    app: string;
    cve: string;
    path: string;
    description?: string;
}

export interface NetworkInfo {
    id: string;
    name: string;
    subnet?: string;
    driver: string;
}

export interface ContainerInfo {
    name: string;
    status: string;
    ports?: string[];
    ips?: string[];
}

export interface ContainerStatus {
    running: boolean;
    containers?: ContainerInfo[];
    start_task?: {
        state?: string;
        message?: string;
    };
}

export interface ExperimentScenarioStats {
    scenario_id: string;
    component: string;
    version: string;
    query_key: string;
    category: string;
    chain_length?: number;
    attack_goal?: string;
    pov_builder?: string;
    exp_builder?: string;
    aifw_bypass_strategy?: string;
    pov_results: boolean[];
    exp_results: boolean[];
    aifw_bypass_results: boolean[];
    pov_success: number;
    pov_total: number;
    pov_rate: number;
    exp_success: number;
    exp_total: number;
    exp_rate: number;
    aifw_bypass_success: number;
    aifw_bypass_total: number;
    aifw_bypass_rate: number;
}

export interface ExperimentCategoryStats {
    pov_success: number;
    pov_total: number;
    pov_rate: number;
    exp_success: number;
    exp_total: number;
    exp_rate: number;
    aifw_bypass_success: number;
    aifw_bypass_total: number;
    aifw_bypass_rate: number;
}

export interface ExperimentStats {
    pov_overall: { success: number; total: number; rate: number };
    exp_overall: { success: number; total: number; rate: number };
    aifw_bypass_overall: { success: number; total: number; rate: number };
    scenario_count: number;
    total_runs: number;
    by_category: Record<string, ExperimentCategoryStats>;
    by_scenario: ExperimentScenarioStats[];
}

export interface ExperimentLookupResponse {
    found: boolean;
    query_key: string;
    data: ExperimentScenarioStats | null;
    suggestions: string[];
}

// ── Generic Fetcher ───────────────────────────────────────────
export async function fetcher<T = any>(url: string): Promise<T> {
    const res = await fetch(url);
    if (!res.ok) {
        throw new Error(`API Error ${res.status}: ${await res.text()}`);
    }
    return res.json();
}

export async function post<T = any>(url: string, body: any): Promise<T> {
    const res = await fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(body)
    });
    if (!res.ok) {
        const err = await res.text();
        throw new Error(`API Error ${res.status}: ${err}`);
    }
    return res.json();
}

// ── Zone / Container APIs ─────────────────────────────────────
export async function fetchZones(): Promise<ZoneMap> {
    return fetcher<ZoneMap>(`${API_BASE}/zones/containers`);
}

export async function createNetworks(dmzSubnet: string, dbSubnet: string) {
    return post(`${API_BASE}/networks/create_defaults`, { dmz_subnet: dmzSubnet, db_subnet: dbSubnet });
}

export async function deployVuln(path: string, zone: string) {
    // Backend expects 'path' and 'zone'. Endpoint is /vulns/start
    return post(`${API_BASE}/vulns/start`, { path, zone });
}

export async function stopVuln(path: string) {
    // Backend endpoint is /vulns/stop
    return post(`${API_BASE}/vulns/stop`, { path });
}

export async function runExploit(containerId: string) {
    // This seems to be legacy or for a specific "one-click" exploit.
    // main.py has /containers/exploit/exec but that takes command_args.
    // Or maybe /attack-chain/run-local?
    // Let's assume it maps to run_local_exploit for now, as that's what 'One Click Pwn' usually implies.
    return post(`${API_BASE}/attack-chain/run-local`, { container_id: containerId });
}

export async function startPivotingAttack(startId: string, targetId?: string) {
    return post(`${API_BASE}/attack-chain/pivoting`, { start_container_id: startId, target_container_id: targetId });
}

export async function getPivotScanResult(containerId: string) {
    return fetcher(`${API_BASE}/attack-chain/scan-result?container_id=${containerId}`);
}

export async function verifyCompromise(containerId: string) {
    return post(`${API_BASE}/containers/verify-compromise`, { container_id: containerId });
}

export async function runLocalExploit(containerId: string) {
    return post(`${API_BASE}/attack-chain/run-local`, { container_id: containerId });
}

export async function executeCustomExploit(containerId: string, commandArgs: string) {
    return post(`${API_BASE}/containers/exploit/exec`, { container_id: containerId, command_args: commandArgs });
}

export async function execInteractiveShell(containerId: string, command: string, workdir: string = '/tmp') {
    return post(`${API_BASE}/containers/shell/exec`, { container_id: containerId, command, workdir });
}


// ── AIFW APIs ─────────────────────────────────────────────────
export async function deployAIFW(): Promise<any> {
    return post(`${API_BASE}/aifw/deploy`, {});
}

export async function stopAIFW(): Promise<any> {
    return post(`${API_BASE}/aifw/stop`, {});
}

export async function getAIFWStatus(): Promise<AIFWStatus> {
    return fetcher<AIFWStatus>(`${API_BASE}/aifw/status`);
}

export async function addInterceptRule(targetIp: string, targetPort: string): Promise<any> {
    return post(`${API_BASE}/aifw/intercept`, { target_ip: targetIp, target_port: targetPort });
}

export async function removeInterceptRule(targetIp: string, targetPort: string): Promise<any> {
    const res = await fetch(`${API_BASE}/aifw/intercept?target_ip=${targetIp}&target_port=${targetPort}`, {
        method: "DELETE",
    });
    return res.json();
}

export async function getInterceptRules(): Promise<{ rules: InterceptRule[] }> {
    return fetcher<{ rules: InterceptRule[] }>(`${API_BASE}/aifw/intercept/rules`);
}

export async function setupRouting(): Promise<any> {
    return post(`${API_BASE}/aifw/routing/setup`, {});
}

export async function getAIFWLogs(tail: number = 200): Promise<any> {
    return fetcher(`${API_BASE}/aifw/logs?tail=${tail}`);
}

export async function clearAIFWLogs(): Promise<any> {
    return post(`${API_BASE}/aifw/logs/clear`, {});
}

export async function analyzeAIFWLogs(params: {
    log_entries?: any[];
    llm_api_url?: string;
    llm_api_key?: string;
    llm_model?: string;
}): Promise<any> {
    return post(`${API_BASE}/aifw/analyze`, params);
}

export async function updateAIFWConfig(config: {
    llm_api_url?: string;
    llm_api_key?: string;
    llm_model?: string;
    aifw_port?: string;
    mode?: string;
}): Promise<any> {
    return post(`${API_BASE}/aifw/config`, config);
}

export async function getAIFWConfig(): Promise<any> {
    return fetcher(`${API_BASE}/aifw/config`);
}

// ── Attack Report APIs ────────────────────────────────────────
export async function generateAttackReport(
    nodes: any[],
    edges: any[],
    onChunk: (data: { type: string; content?: string }) => void,
    config?: { api_key?: string; base_url?: string; model_name?: string },
    signal?: AbortSignal
): Promise<void> {
    const res = await fetch(`${API_BASE}/agent/attack-report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
            nodes,
            edges,
            api_key: config?.api_key || undefined,
            base_url: config?.base_url || undefined,
            model_name: config?.model_name || undefined,
        }),
        signal,
    });

    if (!res.ok) {
        const err = await res.text();
        throw new Error(`API Error ${res.status}: ${err}`);
    }

    const reader = res.body?.getReader();
    if (!reader) throw new Error('No response stream');

    const decoder = new TextDecoder();
    let buffer = '';

    while (true) {
        const { done, value } = await reader.read();
        if (done) break;

        buffer += decoder.decode(value, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
            if (line.startsWith('data: ')) {
                try {
                    const data = JSON.parse(line.slice(6));
                    onChunk(data);
                } catch {
                    // skip malformed lines
                }
            }
        }
    }
}

export async function getAttackReportHistory(): Promise<any[]> {
    const res = await fetcher(`${API_BASE}/agent/attack-report/history`);
    return res?.data || [];
}

export async function getAttackReportContent(filename: string): Promise<string> {
    const res = await fetcher(`${API_BASE}/agent/attack-report/history/${encodeURIComponent(filename)}`);
    return res?.data?.content || '';
}

// ── Experiment APIs ──────────────────────────────────────────
export async function fetchExperimentResults(): Promise<any[]> {
    const res = await fetcher(`${API_BASE}/experiment/results`);
    return res?.data || [];
}

export async function fetchExperimentStats(): Promise<ExperimentStats> {
    const res = await fetcher(`${API_BASE}/experiment/stats`);
    return res?.data || {};
}

export async function fetchExperimentLookup(queryKey: string): Promise<ExperimentLookupResponse> {
    const res = await fetcher(`${API_BASE}/experiment/lookup?query_key=${encodeURIComponent(queryKey)}`);
    return {
        found: res?.found || false,
        query_key: res?.query_key || queryKey,
        data: res?.data || null,
        suggestions: res?.suggestions || [],
    };
}
