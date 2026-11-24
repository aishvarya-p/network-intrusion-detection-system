import React from 'react';

export default function MetricCard({
  title,
  value,
  subtext,
  icon: Icon,
  variant = 'cyan', // cyan, rose, emerald, amber
}) {
  const colorMap = {
    cyan: {
      border: 'border-cyan-500/20 hover:border-cyan-500/40',
      iconBg: 'bg-cyan-500/10 text-cyan-400',
      value: 'text-white',
      glow: 'group-hover:shadow-[0_0_20px_rgba(6,182,212,0.15)]',
    },
    rose: {
      border: 'border-rose-500/20 hover:border-rose-500/40',
      iconBg: 'bg-rose-500/10 text-rose-400',
      value: 'text-rose-400',
      glow: 'group-hover:shadow-[0_0_20px_rgba(244,63,94,0.15)]',
    },
    emerald: {
      border: 'border-emerald-500/20 hover:border-emerald-500/40',
      iconBg: 'bg-emerald-500/10 text-emerald-400',
      value: 'text-emerald-400',
      glow: 'group-hover:shadow-[0_0_20px_rgba(16,185,129,0.15)]',
    },
    amber: {
      border: 'border-amber-500/20 hover:border-amber-500/40',
      iconBg: 'bg-amber-500/10 text-amber-400',
      value: 'text-amber-400',
      glow: 'group-hover:shadow-[0_0_20px_rgba(245,158,11,0.15)]',
    },
  };

  const current = colorMap[variant] || colorMap.cyan;

  return (
    <div
      className={`group relative p-5 rounded-xl bg-[#111827] border ${current.border} transition-all duration-300 ${current.glow}`}
    >
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs font-medium text-gray-400 tracking-wide uppercase font-mono">
          {title}
        </span>
        <div className={`p-2.5 rounded-lg ${current.iconBg}`}>
          <Icon className="w-5 h-5" />
        </div>
      </div>
      <div className="space-y-1">
        <div className={`text-2xl md:text-3xl font-bold tracking-tight font-mono ${current.value}`}>
          {typeof value === 'number' ? value.toLocaleString() : value}
        </div>
        {subtext && (
          <p className="text-xs text-gray-400 font-sans">
            {subtext}
          </p>
        )}
      </div>
    </div>
  );
}
