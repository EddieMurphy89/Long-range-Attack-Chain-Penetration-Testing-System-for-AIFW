"use client";
import React from 'react';
import NetConfig from '@/components/NetConfig';
import ZoneManager from '@/components/ZoneManager';
import { LayoutDashboard } from 'lucide-react';

export default function Dashboard() {
    return (
        <div className="container mx-auto px-4 py-8">
            <div className="mb-8">
                <h1 className="text-3xl font-bold tracking-tight text-slate-900 dark:text-white mb-2 flex items-center gap-3">
                    <span className="inline-flex items-center justify-center w-11 h-11 rounded-2xl bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-300">
                        <LayoutDashboard className="w-6 h-6" />
                    </span>
                    Dashboard
                </h1>
                <p className="text-slate-500 dark:text-slate-400">统一管理网络基础设施、容器分区与靶场环境运行状态。</p>
            </div>

            <div className="space-y-8">
                {/* Zone Manager - Visual Board */}
                <section>
                    <ZoneManager />
                </section>

                {/* Network Configuration */}
                <section>
                    <NetConfig />
                </section>
            </div>
        </div>
    );
}
