"use client";

import { VulnInfo } from "@/lib/api";
import { ExternalLink } from "lucide-react";

export default function VulnCard({ vuln, onClick }: { vuln: VulnInfo; onClick: () => void }) {
  return (
    <div 
        onClick={onClick}
        className="bg-white dark:bg-slate-900 rounded-xl shadow-sm hover:shadow-lg transition-all cursor-pointer border border-slate-200 dark:border-slate-800 overflow-hidden group"
    >
        <div className="p-5">
            <div className="flex items-center justify-between mb-3">
                <span className="px-3 py-1 text-xs font-semibold text-blue-700 dark:text-blue-300 bg-blue-50 dark:bg-blue-900/30 rounded-full border border-blue-100 dark:border-blue-800 truncate max-w-[150px]">
                    {vuln.app}
                </span>
                <ExternalLink className="w-4 h-4 text-slate-300 dark:text-slate-600 group-hover:text-blue-500 transition-colors" />
            </div>
            <h3 className="text-lg font-bold text-slate-800 dark:text-slate-100 mb-2 truncate" title={vuln.cve}>
                {vuln.cve}
            </h3>
            <p className="text-sm text-slate-500 dark:text-slate-400 truncate font-mono bg-slate-50 dark:bg-slate-950 p-1.5 rounded">
                {vuln.path}
            </p>
        </div>
    </div>
  );
}
