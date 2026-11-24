import React from 'react';
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export default function ActivityTimeline({ timeline = [] }) {
  if (!timeline || timeline.length === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-gray-500 text-xs font-mono">
        <span>No recent activity telemetry</span>
      </div>
    );
  }

  // Format data for Recharts
  const chartData = timeline.map((item, index) => {
    let label = `#${index + 1}`;
    if (item.timestamp) {
      try {
        const d = new Date(item.timestamp);
        label = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
      } catch {
        label = `#${index + 1}`;
      }
    }
    return {
      index: index + 1,
      time: label,
      score: item.anomaly_score !== null ? Number(item.anomaly_score) : 0,
      isSuspicious: item.is_suspicious ? 1 : 0,
    };
  });

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
          <defs>
            <linearGradient id="scoreGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="5%" stopColor="#06B6D4" stopOpacity={0.4} />
              <stop offset="95%" stopColor="#06B6D4" stopOpacity={0} />
            </linearGradient>
          </defs>
          <XAxis
            dataKey="time"
            stroke="#6B7280"
            fontSize={10}
            tickLine={false}
            axisLine={{ stroke: '#1F2937' }}
          />
          <YAxis
            domain={[0, 1]}
            stroke="#6B7280"
            fontSize={11}
            tickLine={false}
            axisLine={{ stroke: '#1F2937' }}
            ticks={[0.0, 0.25, 0.5, 0.75, 1.0]}
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
            formatter={(val) => [`${Number(val).toFixed(3)}`, 'Anomaly Score']}
          />
          <Area
            type="monotone"
            dataKey="score"
            stroke="#06B6D4"
            strokeWidth={2}
            fillOpacity={1}
            fill="url(#scoreGradient)"
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  );
}
