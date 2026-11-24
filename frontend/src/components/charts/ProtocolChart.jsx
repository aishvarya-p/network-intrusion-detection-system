import React from 'react';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from 'recharts';

const PROTOCOL_COLORS = {
  TCP: '#06B6D4',  // Cyan
  UDP: '#3B82F6',  // Blue
  ICMP: '#A855F7', // Purple
  OTHER: '#6B7280' // Gray
};

export default function ProtocolChart({ data = {} }) {
  const chartData = Object.entries(data).map(([name, value]) => ({
    name,
    value,
  }));

  const total = chartData.reduce((acc, curr) => acc + curr.value, 0);

  if (chartData.length === 0 || total === 0) {
    return (
      <div className="h-64 flex flex-col items-center justify-center text-gray-500 text-xs font-mono">
        <span>No protocol telemetry yet</span>
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
                fill={PROTOCOL_COLORS[entry.name] || PROTOCOL_COLORS.OTHER}
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
