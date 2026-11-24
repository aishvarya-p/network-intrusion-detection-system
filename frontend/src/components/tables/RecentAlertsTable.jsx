import React from 'react';
import { AlertTriangle, ShieldCheck, ArrowRight } from 'lucide-react';

const SEVERITY_BADGES = {
  CRITICAL: 'bg-red-500/10 text-red-400 border-red-500/30',
  HIGH: 'bg-rose-500/10 text-rose-400 border-rose-500/30',
  MEDIUM: 'bg-amber-500/10 text-amber-400 border-amber-500/30',
  LOW: 'bg-blue-500/10 text-blue-400 border-blue-500/30',
};

export default function RecentAlertsTable({ alerts = [], onViewAll }) {
  if (!alerts || alerts.length === 0) {
    return (
      <div className="p-8 text-center text-gray-500 text-xs font-mono space-y-2">
        <ShieldCheck className="w-8 h-8 text-emerald-500/40 mx-auto" />
        <p>No active security alerts. Network telemetry normal.</p>
      </div>
    );
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs font-mono">
        <thead className="bg-gray-900/60 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
          <tr>
            <th className="py-2.5 px-4">Time</th>
            <th className="py-2.5 px-4">Severity</th>
            <th className="py-2.5 px-4">Type</th>
            <th className="py-2.5 px-4">Source IP</th>
            <th className="py-2.5 px-4">Target IP</th>
            <th className="py-2.5 px-4 text-right">Anomaly Score</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/60 text-gray-300">
          {alerts.map((alert) => {
            const timeStr = alert.timestamp
              ? new Date(alert.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
              : 'N/A';
            const badgeClass = SEVERITY_BADGES[alert.severity] || SEVERITY_BADGES.MEDIUM;

            return (
              <tr key={alert.id} className="hover:bg-gray-800/30 transition">
                <td className="py-3 px-4 text-gray-400">{timeStr}</td>
                <td className="py-3 px-4">
                  <span className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${badgeClass}`}>
                    {alert.severity}
                  </span>
                </td>
                <td className="py-3 px-4 text-white font-medium">{alert.alert_type}</td>
                <td className="py-3 px-4 text-cyan-400">{alert.source_ip}</td>
                <td className="py-3 px-4 text-gray-300">{alert.destination_ip}</td>
                <td className="py-3 px-4 text-right">
                  <span
                    className={`font-semibold ${
                      alert.anomaly_score && alert.anomaly_score >= 0.75
                        ? 'text-rose-400'
                        : 'text-amber-400'
                    }`}
                  >
                    {alert.anomaly_score !== null ? Number(alert.anomaly_score).toFixed(3) : 'N/A'}
                  </span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
