"use client";
import NextLink from 'next/link';
import { cn } from '@/lib/utils';
import { LayoutDashboard, ShieldAlert, Network, Workflow, Sun, Moon, Shield, Wand2, Bot, FlaskConical } from 'lucide-react';
import { useTheme } from './ThemeProvider';

export default function Navbar() {
  const { theme, toggleTheme } = useTheme();

  return (
    <nav className="bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800 transition-colors duration-300">
      <div className="container mx-auto px-4">
        <div className="flex items-center justify-between h-16">
          <div className="flex items-center gap-6">
            <NextLink href="/" className="text-lg font-bold bg-gradient-to-r from-blue-600 to-indigo-600 dark:from-blue-400 dark:to-indigo-400 bg-clip-text text-transparent whitespace-nowrap">
              Vulhub Manager
            </NextLink>
            <div className="hidden lg:flex items-center gap-1">
              <NavLink href="/" icon={<ShieldAlert className="w-4 h-4" />}>Vulnerabilities</NavLink>
              <NavLink href="/dashboard" icon={<LayoutDashboard className="w-4 h-4" />}>Dashboard</NavLink>
              <NavLink href="/targetzone" icon={<Network className="w-4 h-4" />}>TargetZone</NavLink>
              <NavLink href="/attack-chains" icon={<Workflow className="w-4 h-4" />}>Attack Chains</NavLink>
              <NavLink href="/agent" icon={<Bot className="w-4 h-4" />}>AI Agent</NavLink>
              <NavLink href="/aifw" icon={<Shield className="w-4 h-4" />}>AIFW</NavLink>
              <NavLink href="/mutator" icon={<Wand2 className="w-4 h-4" />}>Mutator</NavLink>
              <NavLink href="/experiment" icon={<FlaskConical className="w-4 h-4" />}>Experiment</NavLink>
            </div>
          </div>
          <button
            onClick={toggleTheme}
            className="p-2 rounded-full hover:bg-slate-100 dark:hover:bg-slate-800 text-slate-600 dark:text-slate-400 transition-colors"
            title="Toggle Theme"
          >
            {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
          </button>
        </div>
      </div>
    </nav>
  );
}

function NavLink({ href, children, icon }: { href: string; children: React.ReactNode; icon?: React.ReactNode }) {
  return (
    <NextLink
      href={href}
      className="flex items-center gap-1.5 px-2.5 py-2 text-sm font-medium text-slate-600 dark:text-slate-300 hover:text-slate-900 dark:hover:text-white hover:bg-slate-100 dark:hover:bg-slate-800 rounded-md transition-colors"
    >
      {icon}
      <span>{children}</span>
    </NextLink>
  );
}
