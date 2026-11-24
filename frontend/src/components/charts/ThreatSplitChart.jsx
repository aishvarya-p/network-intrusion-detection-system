import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

export default function ThreatSplitChart({ normal = 0, suspicious = 0 }) {
  const chartData = [
    { name: 'Normal Traffic', value: normal, color: '#10B981' },      // Emerald
    { name: 'Suspicious Traffic', value: suspicious, color: '#F43F5E' }, // Rose
  ];

  const total = normal + suspicious;

  if (total === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-gray-500 text-xs font-mono">
        <span>No traffic evaluated yet</span>
      </div>
    );
  }

  return (
    <div className="h-64 w-full">
      <ResponsiveContainer width="100%" height="100%">
        <PieChart>
          <Pie
            data={chartData}
            cx="50%"
            cy="50%"
            innerRadius={55}
            outerRadius={80}
            paddingAngle={4}
            dataKey="value"
          >
            {chartData.map((entry) => (
              <Cell
                key={`cell-${entry.name}`}
                fill={entry.color}
                stroke="#111827"
                strokeWidth={2}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{
              backgroundColor: '#111827',
              borderColor: '#1F2937',
              borderRadius: '0.5rem',
              color: '#F3F4F6',
              fontSize: '12px',
              fontFamily: 'monospace',
            }}
            formatter={(val, name) => [
              `${val} flows (${Math.round((val / total) * 100)}%)`,
              name,
            ]}
          />
          <Legend
            verticalAlign="bottom"
            height={36}
            iconType="circle"
            wrapperStyle={{ fontSize: '11px', color: '#9CA3AF' }}
          />
        </PieChart>
      </ResponsiveContainer>
    </div>
  );
}
