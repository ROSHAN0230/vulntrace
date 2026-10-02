import React, { useRef, useEffect } from 'react';
import { Terminal, Trash2 } from 'lucide-react';
import { LogLine } from '../types';

interface ExecutionTerminalProps {
  logs: LogLine[];
  onClear: () => void;
  statusText?: string;
  isStreaming?: boolean;
}

export const ExecutionTerminal: React.FC<ExecutionTerminalProps> = ({ logs, onClear, statusText, isStreaming }) => {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [logs]);

  return (
    <div className="bg-surface-2 border border-border-subtle rounded-md overflow-hidden flex flex-col h-full">
      <div className="bg-surface-1 px-4 py-2 border-b border-border-subtle flex items-center justify-between text-xs font-mono">
        <div className="flex items-center gap-2">
          <Terminal className="w-4 h-4 text-emerald-400" />
          <span className="font-semibold text-slate-200">Live Execution Event Stream</span>
          {isStreaming && (
            <span className="flex items-center gap-1.5 text-[10px] text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/40">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
              STREAMING
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {statusText && <span className="text-[11px] text-slate-400">{statusText}</span>}
          <button
            onClick={onClear}
            className="text-slate-500 hover:text-slate-300 transition-colors p-1"
            title="Clear Terminal Output"
          >
            <Trash2 className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="flex-1 p-3 bg-surface-inset font-mono text-[11px] overflow-y-auto space-y-1 select-text"
      >
        {logs.length === 0 ? (
          <div className="text-slate-600 italic py-8 text-center">
            System quiescent. Ready to stream live AST analysis and subprocess execution logs...
          </div>
        ) : (
          logs.map((log) => {
            let textColor = 'text-slate-300';
            let stageBadge = 'bg-surface-3 text-slate-400';

            if (log.level === 'success') {
              textColor = 'text-emerald-300';
              stageBadge = 'bg-emerald-950/40 text-emerald-400 border border-emerald-800/40';
            } else if (log.level === 'warn') {
              textColor = 'text-amber-300';
              stageBadge = 'bg-amber-950/40 text-amber-400 border border-amber-800/40';
            } else if (log.level === 'error') {
              textColor = 'text-rose-300';
              stageBadge = 'bg-rose-950/40 text-rose-400 border border-rose-800/40';
            }

            return (
              <div key={log.id} className="flex items-start gap-2.5 leading-relaxed hover:bg-surface-1/40 px-1 py-0.5 rounded">
                <span className="text-slate-600 select-none text-[10px] shrink-0">{log.timestamp}</span>
                <span className={`px-1 rounded text-[9px] font-bold shrink-0 ${stageBadge}`}>
                  {log.stage}
                </span>
                <span className={`${textColor} break-all flex-1`}>{log.message}</span>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
