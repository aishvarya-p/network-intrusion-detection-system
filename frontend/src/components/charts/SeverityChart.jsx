import React from 'react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const SEVERITY_COLORS = {
  LOW: '#3B82F6',       // Blue
  MEDIUM: '#F59E0B',    // Amber
  HIGH: '#F43F5E',      // Rose
  CRITICAL: '#DC2626',  // Red
};

export default function SeverityChart({ data = {} }) {
  const chartData = [
    { severity: 'LOW', count: data.LOW || 0 },
    { severity: 'MEDIUM', count: data.MEDIUM || 0 },
    { severity: 'HIGH', count: data.HIGH || 0 },
    { severity: 'CRITICAL', count: data.CRITICAL || 0 },
  ];

  const total = chartData.reduce((acc, curr) => acc + curr.count, 0);

  if (total === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-gray-500 text-xs font-mono">
        <span>No security alerts recorded</span>
      </div>
    );
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <XAxis
            dataKey="severity"
            stroke="#6B7280"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: '#1F2937' }}
          />
          <YAxis
            stroke="#6B7280"
            fontSize={11}
            allowDecimals={false}
            tickLine={false}
            axisLine={{ stroke: '#1F2937' }}
          />
          <Tooltip
            contentStyle={{
              backgroundColor: '#111827',
              borderColor: '#1F2937',
              borderRadius: '0.5rem',
              color: '#F3F4F6',
              fontSize: '12px',
              fontFamily: 'monospace',
            }}
            formatter={(val) => [`${val} alerts`, 'Count']}
          />
          <Bar dataKey="count" radius={[4, 4, 0, 0]}>
            {chartData.map((entry) => (
              <Cell key={`bar-${entry.severity}`} fill={SEVERITY_COLORS[entry.severity] || '#3B82F6'} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}
