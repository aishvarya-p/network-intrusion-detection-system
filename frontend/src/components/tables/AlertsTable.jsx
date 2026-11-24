import React from 'react';
import { ChevronLeft, ChevronRight, AlertTriangle, ShieldCheck, CheckCircle2, Clock } from 'lucide-react';

const SEVERITY_BADGES = {
  CRITICAL: 'bg-red-500/15 text-red-400 border-red-500/40 font-bold',
  HIGH: 'bg-rose-500/15 text-rose-400 border-rose-500/40 font-semibold',
  MEDIUM: 'bg-amber-500/15 text-amber-400 border-amber-500/40 font-semibold',
  LOW: 'bg-blue-500/15 text-blue-400 border-blue-500/40 font-medium',
};

export default function AlertsTable({
  items = [],
  total = 0,
  limit = 50,
  offset = 0,
  onPageChange,
  severityFilter,
  onSeverityChange,
  resolvedFilter,
  onResolvedChange,
  isLoading,
}) {
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(Math.ceil(total / limit), 1);

  return (
    <div className="space-y-4">
      {/* Filtering Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-[#111827] border border-gray-800">
        <div className="flex flex-wrap items-center gap-3">
          {/* Severity Filter */}
          <div className="flex items-center space-x-2">
            <label className="text-xs font-mono text-gray-400">Severity:</label>
            <select
              value={severityFilter}
              onChange={(e) => onSeverityChange(e.target.value)}
              className="bg-gray-900 border border-gray-750 text-gray-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">ALL Severities</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="HIGH">HIGH</option>
              <option value="MEDIUM">MEDIUM</option>
              <option value="LOW">LOW</option>
            </select>
          </div>

          {/* Resolution Status Filter */}
          <div className="flex items-center space-x-2">
            <label className="text-xs font-mono text-gray-400">Status:</label>
            <select
              value={resolvedFilter}
              onChange={(e) => onResolvedChange(e.target.value)}
              className="bg-gray-900 border border-gray-750 text-gray-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">ALL Statuses</option>
              <option value="false">Unresolved Only</option>
              <option value="true">Resolved Only</option>
            </select>
          </div>
        </div>

        {/* Total Count Badge */}
        <div className="text-xs font-mono text-gray-400">
          Showing <span className="text-white font-semibold">{items.length}</span> of{' '}
          <span className="text-rose-400 font-semibold">{total.toLocaleString()}</span> alerts
        </div>
      </div>

      {/* Table Container */}
      <div className="rounded-xl bg-[#111827] border border-gray-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-900/80 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
              <tr>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Severity</th>
                <th className="py-3 px-4">Threat Type</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP</th>
                <th className="py-3 px-4 text-center">Score</th>
                <th className="py-3 px-4 text-center">Status</th>
                <th className="py-3 px-4 min-w-[280px]">Incident Description</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 text-gray-300">
              {isLoading ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-gray-500 font-mono">
                    <AlertTriangle className="w-6 h-6 animate-pulse text-rose-500 mx-auto mb-2" />
                    Fetching alerts from security engine...
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-gray-500 font-mono">
                    <ShieldCheck className="w-8 h-8 text-emerald-500/50 mx-auto mb-2" />
                    No security alerts found matching the current filters.
                  </td>
                </tr>
              ) : (
                items.map((alert) => {
                  const timeStr = alert.timestamp
                    ? new Date(alert.timestamp).toLocaleString([], {
                        month: 'short',
                        day: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                      })
                    : 'N/A';
                  const badgeClass = SEVERITY_BADGES[alert.severity] || SEVERITY_BADGES.MEDIUM;

                  return (
                    <tr key={alert.id} className="hover:bg-gray-800/30 transition">
                      <td className="py-3 px-4 text-gray-400 whitespace-nowrap">{timeStr}</td>
                      <td className="py-3 px-4">
                        <span className={`px-2 py-0.5 rounded text-[10px] uppercase border ${badgeClass}`}>
                          {alert.severity}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-bold text-white whitespace-nowrap">{alert.alert_type}</td>
                      <td className="py-3 px-4 text-cyan-400 font-medium">{alert.source_ip}</td>
                      <td className="py-3 px-4 text-gray-300">{alert.destination_ip}</td>
                      <td className="py-3 px-4 text-center font-bold">
                        {alert.anomaly_score !== null ? (
                          <span
                            className={
                              alert.anomaly_score >= 0.75
                                ? 'text-rose-400'
                                : 'text-amber-400'
                            }
                          >
                            {Number(alert.anomaly_score).toFixed(2)}
                          </span>
                        ) : (
                          <span className="text-gray-500">—</span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-center">
                        {alert.is_resolved ? (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            <CheckCircle2 className="w-3 h-3" />
                            <span>RESOLVED</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/30">
                            <Clock className="w-3 h-3" />
                            <span>OPEN</span>
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-4 text-xs font-sans text-gray-300 leading-snug">
                        {alert.description}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Bar */}
        <div className="flex items-center justify-between px-4 py-3 bg-gray-900/80 border-t border-gray-800 text-xs font-mono">
          <div className="text-gray-400">
            Page <span className="text-white font-bold">{currentPage}</span> of{' '}
            <span className="text-white font-bold">{totalPages}</span>
          </div>
          <div className="flex items-center space-x-2">
            <button
              onClick={() => onPageChange(Math.max(offset - limit, 0))}
              disabled={offset <= 0 || isLoading}
              className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed transition"
            >
              <ChevronLeft className="w-4 h-4" />
              <span>Previous</span>
            </button>
            <button
              onClick={() => onPageChange(offset + limit)}
              disabled={offset + limit >= total || isLoading}
              className="flex items-center space-x-1 px-3 py-1.5 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 disabled:opacity-40 disabled:cursor-not-allowed transition"
            >
              <span>Next</span>
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
