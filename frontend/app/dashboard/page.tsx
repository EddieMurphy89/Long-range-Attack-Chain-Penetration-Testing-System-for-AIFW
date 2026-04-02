"use client";
import React from 'react';
import NetConfig from '@/components/NetConfig';
import ZoneManager from '@/components/ZoneManager';

export default function Dashboard() {
    return (
        <div className="container mx-auto px-4 py-8">
            <div className="mb-8">
                <h1 className="text-3xl font-bold text-slate-900 dark:text-white mb-2">Dashboard</h1>
                <p className="text-slate-500 dark:text-slate-400">Manage network infrastructure and container zones.</p>
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
