"use client";
import React, { useEffect, useState } from 'react';
import { NetworkInfo, fetcher, post } from '@/lib/api';
import { Save, Trash2, RotateCw, Network, PlusCircle } from 'lucide-react';

export default function NetConfig() {
    const [networks, setNetworks] = useState<NetworkInfo[]>([]);
    const [loading, setLoading] = useState(false);

    // Subnet State
    const [dmzSubnet, setDmzSubnet] = useState('192.168.6.0/24');
    const [dbSubnet, setDbSubnet] = useState('192.168.5.0/24');

    useEffect(() => {
        loadConfig();
        loadNetworks();
    }, []);

    const loadConfig = () => {
        const stored = localStorage.getItem('vulhub_net_config');
        if (stored) {
            try {
                const parsed = JSON.parse(stored);
                if (parsed.dmzSubnet) setDmzSubnet(parsed.dmzSubnet);
                if (parsed.dbSubnet) setDbSubnet(parsed.dbSubnet);
            } catch (e) { console.error(e); }
        }
    };

    const loadNetworks = async () => {
        setLoading(true);
        try {
            const data = await fetcher('/api/networks');
            setNetworks(data);
        } catch (e) {
            console.error(e);
        } finally {
            setLoading(false);
        }
    };

    const handleSaveAndCreate = async () => {
        // Save local
        localStorage.setItem('vulhub_net_config', JSON.stringify({ dmzSubnet, dbSubnet }));

        // Create remote
        try {
            await post('/api/networks/create_defaults', { dmz_subnet: dmzSubnet, db_subnet: dbSubnet });
            alert('Settings saved and network creation requested.');
            loadNetworks();
        } catch (e: any) {
            alert('Error: ' + e.message);
        }
    };

    const handleDelete = async (name: string) => {
        if (!confirm(`Delete network "${name}"? Only do this if no containers are attached.`)) return;
        try {
            await post('/api/networks/delete', { name });
            loadNetworks();
        } catch (e: any) {
            alert('Delete failed: ' + e.message);
        }
    };

    return (
        <div className="bg-white dark:bg-slate-800 rounded-xl shadow-sm border border-slate-200 dark:border-slate-700 overflow-hidden">
            <div className="px-6 py-4 border-b border-slate-100 dark:border-slate-700 bg-slate-50/50 dark:bg-slate-800/50 flex items-center gap-2">
                <Network className="w-5 h-5 text-blue-600 dark:text-blue-400" />
                <h2 className="font-bold text-slate-800 dark:text-slate-200">Network Configuration</h2>
            </div>

            <div className="p-6">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">DMZ Subnet (Zone A)</label>
                        <input
                            type="text"
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm text-slate-600 dark:text-slate-300"
                            value={dmzSubnet}
                            onChange={(e) => setDmzSubnet(e.target.value)}
                        />
                    </div>
                    <div>
                        <label className="block text-sm font-medium text-slate-700 dark:text-slate-300 mb-2">DB Subnet (Zone B)</label>
                        <input
                            type="text"
                            className="w-full px-3 py-2 bg-slate-50 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500 font-mono text-sm text-slate-600 dark:text-slate-300"
                            value={dbSubnet}
                            onChange={(e) => setDbSubnet(e.target.value)}
                        />
                    </div>
                </div>

                <div className="flex justify-end border-b border-slate-100 dark:border-slate-700 pb-6 mb-6">
                    <button
                        onClick={handleSaveAndCreate}
                        className="flex items-center gap-2 px-4 py-2 bg-blue-600 dark:bg-blue-500 text-white rounded-lg hover:bg-blue-700 dark:hover:bg-blue-600 transition"
                    >
                        <Save className="w-4 h-4" /> Save & Create Networks
                    </button>
                </div>

                {/* Existing Networks Table */}
                <div>
                    <div className="flex justify-between items-center mb-4">
                        <h3 className="text-sm font-semibold text-slate-600 dark:text-slate-400 uppercase tracking-wider">Active Docker Networks</h3>
                        <button onClick={loadNetworks} className="text-blue-600 dark:text-blue-400 hover:text-blue-800 dark:hover:text-blue-300">
                            <RotateCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                        </button>
                    </div>

                    <div className="overflow-x-auto border border-slate-200 dark:border-slate-700 rounded-lg">
                        <table className="w-full text-sm text-left">
                            <thead className="bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400 font-medium">
                                <tr>
                                    <th className="px-4 py-3">Name</th>
                                    <th className="px-4 py-3">Subnet</th>
                                    <th className="px-4 py-3">Driver</th>
                                    <th className="px-4 py-3 text-right">Action</th>
                                </tr>
                            </thead>
                            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
                                {networks.map(net => (
                                    <tr key={net.id} className="hover:bg-slate-50/50 dark:hover:bg-slate-800/50">
                                        <td className="px-4 py-3 font-medium text-slate-800 dark:text-slate-200">
                                            {net.name}
                                            {(net.name === 'vulhub_net_dmz_a' || net.name === 'vulhub_net_db_b') && (
                                                <span className="ml-2 text-[10px] bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-400 px-1.5 py-0.5 rounded font-bold uppercase">System</span>
                                            )}
                                        </td>
                                        <td className="px-4 py-3 font-mono text-slate-600 dark:text-slate-400">{net.subnet || '-'}</td>
                                        <td className="px-4 py-3 text-slate-500 dark:text-slate-400">{net.driver}</td>
                                        <td className="px-4 py-3 text-right">
                                            {!['bridge', 'host', 'none'].includes(net.name) && (
                                                <button
                                                    onClick={() => handleDelete(net.name)}
                                                    className="text-red-500 hover:text-red-700 dark:hover:text-red-400 p-1 hover:bg-red-50 dark:hover:bg-red-500/10 rounded"
                                                    title="Delete Network"
                                                >
                                                    <Trash2 className="w-4 h-4" />
                                                </button>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                                {networks.length === 0 && (
                                    <tr><td colSpan={4} className="p-4 text-center text-slate-400 dark:text-slate-500">No networks found</td></tr>
                                )}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    );
}
