import React from 'react';
import { Activity, ShieldAlert, ShieldCheck, AlertTriangle, ArrowUpRight } from 'lucide-react';
import MetricCard from '../components/MetricCard';
import ProtocolChart from '../components/charts/ProtocolChart';
import ThreatSplitChart from '../components/charts/ThreatSplitChart';
import SeverityChart from '../components/charts/SeverityChart';
import ActivityTimeline from '../components/charts/ActivityTimeline';
import RecentAlertsTable from '../components/tables/RecentAlertsTable';

export default function DashboardPage({ stats, recentAlerts = [], onNavigateToAlerts }) {
  const total = stats?.total_traffic || 0;
  const suspicious = stats?.suspicious_traffic || 0;
  const normal = stats?.normal_traffic || 0;
  const alertsCount = stats?.total_alerts || 0;
  const threatRate = stats?.threat_percentage || 0;

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-gray-800 pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <span>Security Operations Center</span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-400 border border-cyan-800/40">
              SOC MONITORING
            </span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Network Flow Analysis & Anomaly Detection using Isolation Forest scoring and heuristic threat categorization.
          </p>
        </div>

        {/* Global Threat Level Pill */}
        <div className="flex items-center space-x-2 bg-gray-900 border border-gray-800 px-3.5 py-1.5 rounded-xl text-xs font-mono">
          <span className="text-gray-400">Threat Index:</span>
          <span
            className={`font-bold ${
              threatRate >= 30
                ? 'text-red-400'
                : threatRate >= 10
                ? 'text-amber-400'
                : 'text-emerald-400'
            }`}
          >
            {threatRate.toFixed(1)}%
          </span>
        </div>
      </div>

      {/* 4 Primary KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <MetricCard
          title="Total Flows Inspected"
          value={total}
          subtext="Total network flow records analyzed"
          icon={Activity}
          variant="cyan"
        />
        <MetricCard
          title="Normal Traffic"
          value={normal}
          subtext={`${total > 0 ? Math.round((normal / total) * 100) : 100}% baseline compliance`}
          icon={ShieldCheck}
          variant="emerald"
        />
        <MetricCard
          title="Suspicious Activity"
          value={suspicious}
          subtext="Anomalies and rule deviations"
          icon={ShieldAlert}
          variant="rose"
        />
        <MetricCard
          title="Security Alerts"
          value={alertsCount}
          subtext="Actionable SOC incident records"
          icon={AlertTriangle}
          variant="amber"
        />
      </div>

      {/* Recharts Analytics Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Chart 1: Protocol Distribution */}
        <div className="p-5 rounded-xl bg-[#111827] border border-gray-800 shadow-lg">
          <div className="flex items-center justify-between mb-4 border-b border-gray-800/60 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-white">Protocol Distribution</h3>
              <p className="text-[11px] text-gray-400">Traffic volume breakdown by network transport layer</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
              TCP / UDP / ICMP
            </span>
          </div>
          <ProtocolChart data={stats?.traffic_by_protocol} />
        </div>

        {/* Chart 2: Normal vs Suspicious Ratio */}
        <div className="p-5 rounded-xl bg-[#111827] border border-gray-800 shadow-lg">
          <div className="flex items-center justify-between mb-4 border-b border-gray-800/60 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-white">Traffic Health Ratio</h3>
              <p className="text-[11px] text-gray-400">Proportion of verified normal flows versus detected anomalies</p>
            </div>
            <span className="text-[10px] font-mono text-emerald-400 bg-emerald-950/60 px-2 py-0.5 rounded border border-emerald-800/40">
              HEALTH SPLIT
            </span>
          </div>
          <ThreatSplitChart normal={normal} suspicious={suspicious} />
        </div>

        {/* Chart 3: Alerts Grouped by Severity */}
        <div className="p-5 rounded-xl bg-[#111827] border border-gray-800 shadow-lg">
          <div className="flex items-center justify-between mb-4 border-b border-gray-800/60 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-white">Alerts by Severity</h3>
              <p className="text-[11px] text-gray-400">Distribution of incidents across SOC triage levels</p>
            </div>
            <span className="text-[10px] font-mono text-amber-400 bg-amber-950/60 px-2 py-0.5 rounded border border-amber-800/40">
              TRIAGE
            </span>
          </div>
          <SeverityChart data={stats?.alerts_by_severity} />
        </div>

        {/* Chart 4: Traffic Activity & Anomaly Score Over Time */}
        <div className="p-5 rounded-xl bg-[#111827] border border-gray-800 shadow-lg">
          <div className="flex items-center justify-between mb-4 border-b border-gray-800/60 pb-3">
            <div>
              <h3 className="text-sm font-semibold text-white">Anomaly Score Timeline</h3>
              <p className="text-[11px] text-gray-400">Sequential flow inspection decision scores (0.0 normal - 1.0 critical)</p>
            </div>
            <span className="text-[10px] font-mono text-cyan-400 bg-cyan-950/60 px-2 py-0.5 rounded border border-cyan-800/40">
              TIME SERIES
            </span>
          </div>
          <ActivityTimeline timeline={stats?.recent_timeline} />
        </div>
      </div>

      {/* Recent Security Alerts Preview */}
      <div className="p-5 rounded-xl bg-[#111827] border border-gray-800 shadow-lg">
        <div className="flex items-center justify-between mb-4 border-b border-gray-800/60 pb-3">
          <div>
            <h3 className="text-sm font-semibold text-white">Recent Security Alerts</h3>
            <p className="text-[11px] text-gray-400">Latest threat detections requiring analyst review</p>
          </div>
          <button
            onClick={onNavigateToAlerts}
            className="flex items-center space-x-1 text-xs text-cyan-400 hover:text-cyan-300 font-mono transition"
          >
            <span>View All Alerts</span>
            <ArrowUpRight className="w-3.5 h-3.5" />
          </button>
        </div>
        <RecentAlertsTable alerts={recentAlerts.slice(0, 5)} />
      </div>
    </div>
  );
}
