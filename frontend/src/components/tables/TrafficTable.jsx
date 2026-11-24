import React from 'react';
import { ChevronLeft, ChevronRight, Activity, ShieldAlert, ShieldCheck } from 'lucide-react';

export default function TrafficTable({
  items = [],
  total = 0,
  limit = 50,
  offset = 0,
  onPageChange,
  protocolFilter,
  onProtocolChange,
  suspiciousFilter,
  onSuspiciousChange,
  isLoading,
}) {
  const currentPage = Math.floor(offset / limit) + 1;
  const totalPages = Math.max(Math.ceil(total / limit), 1);

  return (
    <div className="space-y-4">
      {/* Filtering Bar */}
      <div className="flex flex-wrap items-center justify-between gap-3 p-3.5 rounded-xl bg-[#111827] border border-gray-800">
        <div className="flex flex-wrap items-center gap-3">
          {/* Protocol Filter */}
          <div className="flex items-center space-x-2">
            <label className="text-xs font-mono text-gray-400">Protocol:</label>
            <select
              value={protocolFilter}
              onChange={(e) => onProtocolChange(e.target.value)}
              className="bg-gray-900 border border-gray-750 text-gray-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">ALL Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
              <option value="ICMP">ICMP</option>
            </select>
          </div>

          {/* Suspicious Status Filter */}
          <div className="flex items-center space-x-2">
            <label className="text-xs font-mono text-gray-400">Status:</label>
            <select
              value={suspiciousFilter}
              onChange={(e) => onSuspiciousChange(e.target.value)}
              className="bg-gray-900 border border-gray-750 text-gray-200 text-xs rounded-lg px-2.5 py-1.5 focus:outline-none focus:border-cyan-500 font-mono"
            >
              <option value="ALL">ALL Statuses</option>
              <option value="true">Suspicious Only</option>
              <option value="false">Normal Only</option>
            </select>
          </div>
        </div>

        {/* Total Count Badge */}
        <div className="text-xs font-mono text-gray-400">
          Showing <span className="text-white font-semibold">{items.length}</span> of{' '}
          <span className="text-cyan-400 font-semibold">{total.toLocaleString()}</span> flows
        </div>
      </div>

      {/* Table Container */}
      <div className="rounded-xl bg-[#111827] border border-gray-800 overflow-hidden shadow-xl">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-gray-900/80 text-gray-400 uppercase text-[10px] tracking-wider border-b border-gray-800">
              <tr>
                <th className="py-3 px-4">Time</th>
                <th className="py-3 px-4">Source IP</th>
                <th className="py-3 px-4">Destination IP:Port</th>
                <th className="py-3 px-4">Proto</th>
                <th className="py-3 px-4 text-right">Packets</th>
                <th className="py-3 px-4 text-right">Bytes</th>
                <th className="py-3 px-4 text-right">Duration</th>
                <th className="py-3 px-4 text-center">Score</th>
                <th className="py-3 px-4 text-center">Status</th>
                <th className="py-3 px-4">Detection Detail</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60 text-gray-300">
              {isLoading ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-gray-500 font-mono">
                    <Activity className="w-6 h-6 animate-pulse text-cyan-500 mx-auto mb-2" />
                    Fetching network flows from database...
                  </td>
                </tr>
              ) : items.length === 0 ? (
                <tr>
                  <td colSpan={10} className="py-12 text-center text-gray-500 font-mono">
                    No network flows match the selected criteria.
                  </td>
                </tr>
              ) : (
                items.map((flow) => {
                  const timeStr = flow.timestamp
                    ? new Date(flow.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
                    : 'N/A';
                  return (
                    <tr
                      key={flow.id}
                      className={`hover:bg-gray-800/30 transition ${
                        flow.is_suspicious ? 'bg-rose-950/10' : ''
                      }`}
                    >
                      <td className="py-2.5 px-4 text-gray-400">{timeStr}</td>
                      <td className="py-2.5 px-4 text-cyan-300 font-medium">{flow.source_ip}</td>
                      <td className="py-2.5 px-4 text-gray-200">
                        {flow.destination_ip}:<span className="text-gray-400">{flow.destination_port}</span>
                      </td>
                      <td className="py-2.5 px-4">
                        <span className="px-1.5 py-0.5 rounded bg-gray-800 text-[10px] text-gray-300">
                          {flow.protocol}
                        </span>
                      </td>
                      <td className="py-2.5 px-4 text-right">{flow.packet_count.toLocaleString()}</td>
                      <td className="py-2.5 px-4 text-right">
                        {flow.byte_count >= 1048576
                          ? `${(flow.byte_count / 1048576).toFixed(2)} MB`
                          : flow.byte_count >= 1024
                          ? `${(flow.byte_count / 1024).toFixed(1)} KB`
                          : `${flow.byte_count} B`}
                      </td>
                      <td className="py-2.5 px-4 text-right text-gray-400">{Number(flow.duration).toFixed(2)}s</td>
                      <td className="py-2.5 px-4 text-center font-bold">
                        {flow.anomaly_score !== null ? (
                          <span
                            className={
                              flow.anomaly_score >= 0.75
                                ? 'text-rose-400'
                                : flow.anomaly_score >= 0.50
                                ? 'text-amber-400'
                                : 'text-emerald-400'
                            }
                          >
                            {Number(flow.anomaly_score).toFixed(2)}
                          </span>
                        ) : (
                          <span className="text-gray-500">—</span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-center">
                        {flow.is_suspicious ? (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/30">
                            <ShieldAlert className="w-3 h-3" />
                            <span>SUSPICIOUS</span>
                          </span>
                        ) : (
                          <span className="inline-flex items-center space-x-1 px-2 py-0.5 rounded-full text-[10px] font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                            <ShieldCheck className="w-3 h-3" />
                            <span>NORMAL</span>
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-4 text-xs font-sans text-gray-400 truncate max-w-[200px]" title={flow.detected_category || 'Normal Activity'}>
                        {flow.detected_category || (
                          <span className="text-gray-600 font-mono text-[10px]">NORMAL</span>
                        )}
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
