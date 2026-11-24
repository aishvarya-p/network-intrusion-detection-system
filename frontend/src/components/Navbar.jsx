import React from 'react';
import { Shield, Activity, RefreshCw, Zap, Server, Cpu } from 'lucide-react';

export default function Navbar({
  health,
  isOnline,
  isRefreshing,
  onRefresh,
  onOpenSimulate,
}) {
  return (
    <header className="h-16 border-b border-gray-800 bg-[#0E1524] px-4 md:px-6 flex items-center justify-between sticky top-0 z-30">
      {/* Brand & Project Identity */}
      <div className="flex items-center space-x-3">
        <div className="p-2 rounded-lg bg-cyan-950/60 border border-cyan-500/30 text-cyan-400">
          <Shield className="w-6 h-6" />
        </div>
        <div>
          <div className="flex items-center space-x-2">
            <h1 className="text-lg font-bold tracking-wider text-white">NIDS</h1>
            <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-cyan-900/50 text-cyan-300 border border-cyan-700/50">
              AI SOC v0.1
            </span>
          </div>
          <p className="text-xs text-gray-400 hidden sm:block">
            AI-Powered Network Security Monitoring Dashboard
          </p>
        </div>
      </div>

      {/* Telemetry Status Pills & Actions */}
      <div className="flex items-center space-x-2 md:space-x-4">
        {/* Backend Connection State */}
        <div className="flex items-center space-x-2 px-3 py-1.5 rounded-full bg-gray-900 border border-gray-800 text-xs font-mono">
          <span
            className={`w-2.5 h-2.5 rounded-full ${
              isOnline ? 'bg-emerald-400 radar-live' : 'bg-rose-500'
            }`}
          />
          <span className="text-gray-300 hidden md:inline">Backend:</span>
          <span className={isOnline ? 'text-emerald-400 font-semibold' : 'text-rose-400 font-semibold'}>
            {isOnline ? 'ONLINE' : 'OFFLINE'}
          </span>
        </div>

        {/* Model Loaded Status */}
        {health && (
          <div className="hidden lg:flex items-center space-x-1.5 px-3 py-1.5 rounded-full bg-gray-900 border border-gray-800 text-xs font-mono text-gray-300">
            <Cpu className="w-3.5 h-3.5 text-cyan-400" />
            <span>Isolation Forest:</span>
            <span className={health.model_loaded ? 'text-cyan-400 font-semibold' : 'text-amber-400'}>
              {health.model_loaded ? 'ACTIVE' : 'UNLOADED'}
            </span>
          </div>
        )}

        {/* Manual Refresh Button */}
        <button
          onClick={onRefresh}
          disabled={isRefreshing}
          title="Refresh Data"
          className="p-2 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-gray-300 hover:text-white transition disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
        </button>

        {/* Quick Simulate Trigger */}
        <button
          onClick={onOpenSimulate}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white font-medium text-xs shadow-lg shadow-cyan-950 transition active:scale-95"
        >
          <Zap className="w-3.5 h-3.5 fill-current" />
          <span>Simulate Traffic</span>
        </button>
      </div>
    </header>
  );
}
