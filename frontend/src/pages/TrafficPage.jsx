import React, { useState, useEffect, useCallback } from 'react';
import { Activity, RefreshCw, AlertCircle } from 'lucide-react';
import { api } from '../services/api';
import TrafficTable from '../components/tables/TrafficTable';

export default function TrafficPage() {
  const [trafficData, setTrafficData] = useState({ items: [], total: 0 });
  const [protocol, setProtocol] = useState('ALL');
  const [isSuspicious, setIsSuspicious] = useState('ALL');
  const [offset, setOffset] = useState(0);
  const limit = 50;
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState(null);

  const loadTraffic = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const data = await api.getTraffic({
        limit,
        offset,
        protocol: protocol !== 'ALL' ? protocol : null,
        isSuspicious: isSuspicious !== 'ALL' ? isSuspicious : null,
      });
      setTrafficData(data);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to fetch network traffic records.');
    } finally {
      setIsLoading(false);
    }
  }, [offset, protocol, isSuspicious]);

  useEffect(() => {
    loadTraffic();
  }, [loadTraffic]);

  const handleProtocolChange = (val) => {
    setProtocol(val);
    setOffset(0); // Reset to first page
  };

  const handleSuspiciousChange = (val) => {
    setIsSuspicious(val);
    setOffset(0); // Reset to first page
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-gray-800 pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <Activity className="w-5 h-5 text-cyan-400" />
            <span>Network Traffic Analysis</span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Full 5-tuple network flow records with Isolation Forest scores and heuristic categorization.
          </p>
        </div>

        <button
          onClick={loadTraffic}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-xs text-gray-300 font-mono transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Flows</span>
        </button>
      </div>

      {/* Error Banner */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2 font-mono">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Traffic Table */}
      <TrafficTable
        items={trafficData.items}
        total={trafficData.total}
        limit={limit}
        offset={offset}
        onPageChange={setOffset}
        protocolFilter={protocol}
        onProtocolChange={handleProtocolChange}
        suspiciousFilter={isSuspicious}
        onSuspiciousChange={handleSuspiciousChange}
        isLoading={isLoading}
      />
    </div>
  );
}
