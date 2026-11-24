import React from 'react';
import { LayoutDashboard, Activity, AlertTriangle, UploadCloud, Terminal } from 'lucide-react';

export default function Sidebar({ activeTab, onSelectTab, alertsCount = 0 }) {
  const navigationItems = [
    {
      id: 'dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      badge: null,
    },
    {
      id: 'traffic',
      label: 'Network Traffic',
      icon: Activity,
      badge: null,
    },
    {
      id: 'alerts',
      label: 'Security Alerts',
      icon: AlertTriangle,
      badge: alertsCount > 0 ? alertsCount : null,
      badgeColor: 'bg-rose-500/20 text-rose-400 border border-rose-500/30',
    },
    {
      id: 'upload',
      label: 'CSV Upload',
      icon: UploadCloud,
      badge: null,
    },
  ];

  return (
    <aside className="w-64 border-r border-gray-800 bg-[#0E1524] flex flex-col justify-between flex-shrink-0">
      <div className="p-4 space-y-6">
        {/* Navigation Section */}
        <div>
          <p className="px-3 text-[11px] font-mono tracking-wider text-gray-500 uppercase mb-3">
            Navigation
          </p>
          <nav className="space-y-1">
            {navigationItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => onSelectTab(item.id)}
                  className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-sm font-medium transition-all ${
                    isActive
                      ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-sm'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/60 border border-transparent'
                  }`}
                >
                  <div className="flex items-center space-x-3">
                    <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-gray-400'}`} />
                    <span>{item.label}</span>
                  </div>
                  {item.badge !== null && (
                    <span
                      className={`text-[11px] font-mono font-semibold px-2 py-0.5 rounded-full ${
                        item.badgeColor || 'bg-gray-800 text-gray-300'
                      }`}
                    >
                      {item.badge}
                    </span>
                  )}
                </button>
              );
            })}
          </nav>
        </div>

        {/* Security Ops Notice Card */}
        <div className="p-3.5 rounded-xl bg-gray-900/80 border border-gray-800/80 text-xs space-y-2">
          <div className="flex items-center space-x-2 text-cyan-400 font-semibold">
            <Terminal className="w-3.5 h-3.5" />
            <span>SOC Defense Mode</span>
          </div>
          <p className="text-gray-400 leading-relaxed text-[11px]">
            Synthetic and CSV Flow Analysis Active. Isolation Forest scores statistical deviations while heuristic rules identify attack signatures.
          </p>
        </div>
      </div>

      {/* Footer Info */}
      <div className="p-4 border-t border-gray-800/80 text-[11px] text-gray-500 flex justify-between items-center font-mono">
        <span>SQLite + FastAPI</span>
        <span>RFC 5737 WAN</span>
      </div>
    </aside>
  );
}
