"use client";

import React, { useEffect, useState } from 'react';
import VulnCard from '@/components/VulnCard';
import VulnModal from '@/components/VulnModal';
import { VulnInfo } from '@/lib/api';
import { Search } from 'lucide-react';

export default function Home() {
  const [vulns, setVulns] = useState<VulnInfo[]>([]);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState('');
  const [selectedVuln, setSelectedVuln] = useState<VulnInfo | null>(null);

  useEffect(() => {
    fetch('/api/vulns')
      .then(res => res.json())
      .then(data => {
        setVulns(data);
        setLoading(false);
      })
      .catch(err => {
        console.error(err);
        setLoading(false);
      });
  }, []);

  const filtered = vulns.filter(v => 
    v.app.toLowerCase().includes(search.toLowerCase()) || 
    v.cve.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="container mx-auto px-4 py-8">
      {/* Search Header */}
      <div className="mb-8">
        <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">Vulnerabilities</h1>
        <p className="text-slate-500 dark:text-slate-400 mb-6">Select a vulnerability environment to deploy.</p>
        
        <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-400 w-5 h-5" />
            <input 
                type="text" 
                placeholder="Search app or CVE..." 
                className="w-full pl-10 pr-4 py-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 focus:outline-none focus:ring-2 focus:ring-blue-500/20 dark:focus:ring-blue-500/10 focus:border-blue-500 transition-all shadow-sm text-slate-700 dark:text-slate-200 placeholder:text-slate-400"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
            />
        </div>
      </div>

      {/* Grid */}
      {loading ? (
        <div className="flex justify-center py-20">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
            {filtered.map(v => (
                <VulnCard 
                    key={v.path} 
                    vuln={v} 
                    onClick={() => setSelectedVuln(v)} 
                />
            ))}
            {filtered.length === 0 && (
                <div className="col-span-full text-center py-20 text-slate-500">
                    No vulnerabilities found matching your search.
                </div>
            )}
        </div>
      )}

      {selectedVuln && (
        <VulnModal 
            vuln={selectedVuln} 
            onClose={() => setSelectedVuln(null)} 
        />
      )}
    </div>
  );
}
