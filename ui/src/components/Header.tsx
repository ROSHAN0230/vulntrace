import { ShieldCheck, Cpu, Cloud, Search } from 'lucide-react';
import { SystemHealthResponse } from '../types';

interface HeaderProps {
  health: SystemHealthResponse | null;
  loading?: boolean;
}

export const Header: React.FC<HeaderProps> = ({ health, loading }) => {
  const getStatusBadge = (key: string, label: string, icon: React.ReactNode) => {
    const prov = health?.providers[key];
    const isOnline = prov?.status === 'ONLINE';
    const isDenied = prov?.status === 'PERMISSION_DENIED';
    const isMissing = prov?.status === 'MISSING_KEY';

    let badgeColor = 'bg-surface-2 border-border-subtle text-slate-400';
    let dotColor = 'bg-slate-500';

    if (isOnline) {
      badgeColor = 'bg-emerald-950/40 border-emerald-600/40 text-emerald-300';
      dotColor = 'bg-emerald-400';
    } else if (isDenied) {
      badgeColor = 'bg-amber-950/40 border-amber-600/40 text-amber-300';
      dotColor = 'bg-amber-400';
    } else if (isMissing) {
      badgeColor = 'bg-rose-950/30 border-rose-800/40 text-rose-300';
      dotColor = 'bg-rose-500';
    }

    return (
      <div 
        className={`flex items-center gap-2 px-2.5 py-1 rounded border text-xs font-mono transition-all ${badgeColor}`}
        title={prov?.detail || `${label}: ${prov?.status || 'UNKNOWN'}`}
      >
        <span className="opacity-70">{icon}</span>
        <span className="font-medium text-slate-200">{label}</span>
        <span className={`w-1.5 h-1.5 rounded-full ${dotColor} ${isOnline ? 'animate-pulse' : ''}`} />
        <span className="text-[10px] uppercase tracking-wider opacity-80">
          {prov ? (isOnline ? `${prov.latency_ms}ms` : prov.status.replace('_', ' ')) : 'CHECKING...'}
        </span>
      </div>
    );
  };

  return (
    <header className="border-b border-border-subtle bg-surface-1 px-6 py-3.5 flex flex-wrap items-center justify-between gap-4">
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded bg-emerald-500/10 border border-emerald-500/30 flex items-center justify-center text-emerald-400 shadow-inner">
          <ShieldCheck className="w-5 h-5" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-base font-bold tracking-tight text-white font-sans">VulnTrace</h1>
            <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 font-semibold flex items-center gap-1">
              {loading && <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-ping" />}
              v0.1.0 DEVSECOPS
            </span>
          </div>
          <p className="text-xs text-slate-400 font-mono tracking-tight">
            Autonomous CVE Reproduction & Verified Patching Agent
          </p>
        </div>
      </div>

      <div className="flex items-center flex-wrap gap-2">
        {getStatusBadge('nebius_token_factory', 'Nemotron 3 Ultra', <Cpu className="w-3.5 h-3.5 text-sky-400" />)}
        {getStatusBadge('contree_sandboxes', 'ConTree Cloud', <Cloud className="w-3.5 h-3.5 text-amber-400" />)}
        {getStatusBadge('tavily_search', 'Tavily Search', <Search className="w-3.5 h-3.5 text-indigo-400" />)}
        {getStatusBadge('osv_dev', 'OSV Advisory', <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />)}
      </div>
    </header>
  );
};
