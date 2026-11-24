import React, { useState, useEffect, useCallback } from 'react';
import { AlertTriangle, RefreshCw, AlertCircle } from 'lucide-react';
import { api } from '../services/api';
import AlertsTable from '../components/tables/AlertsTable';

export default function AlertsPage() {
  const [alertsData, setAlertsData] = useState({ items: [], total: 0 });
  const [severity, setSeverity] = useState('ALL');
  const [isResolved, setIsResolved] = useState('ALL');
  const [offset, setOffset] = useState(0);
  const limit = 50;
  const [isLoading, setIsLoading] = useState(true);
  const [errorMessage, setErrorMessage] = useState(null);

  const loadAlerts = useCallback(async () => {
    setIsLoading(true);
    setErrorMessage(null);
    try {
      const data = await api.getAlerts({
        limit,
        offset,
        severity: severity !== 'ALL' ? severity : null,
        isResolved: isResolved !== 'ALL' ? isResolved : null,
      });
      setAlertsData(data);
    } catch (err) {
      setErrorMessage(err.message || 'Failed to fetch security alerts.');
    } finally {
      setIsLoading(false);
    }
  }, [offset, severity, isResolved]);

  useEffect(() => {
    loadAlerts();
  }, [loadAlerts]);

  const handleSeverityChange = (val) => {
    setSeverity(val);
    setOffset(0);
  };

  const handleResolvedChange = (val) => {
    setIsResolved(val);
    setOffset(0);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-gray-800 pb-4">
        <div>
          <h2 className="text-xl font-bold tracking-tight text-white flex items-center space-x-2">
            <AlertTriangle className="w-5 h-5 text-rose-400" />
            <span>Security Incidents & Alerts</span>
          </h2>
          <p className="text-xs text-gray-400 mt-0.5">
            Flagged behavioral anomalies and heuristic attack signature matches.
          </p>
        </div>

        <button
          onClick={loadAlerts}
          disabled={isLoading}
          className="flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-gray-900 hover:bg-gray-800 border border-gray-800 text-xs text-gray-300 font-mono transition"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
          <span>Refresh Alerts</span>
        </button>
      </div>

      {/* Error Banner */}
      {errorMessage && (
        <div className="p-4 rounded-xl bg-rose-950/40 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2 font-mono">
          <AlertCircle className="w-4 h-4 flex-shrink-0" />
          <span>{errorMessage}</span>
        </div>
      )}

      {/* Alerts Table */}
      <AlertsTable
        items={alertsData.items}
        total={alertsData.total}
        limit={limit}
        offset={offset}
        onPageChange={setOffset}
        severityFilter={severity}
        onSeverityChange={handleSeverityChange}
        resolvedFilter={isResolved}
        onResolvedChange={handleResolvedChange}
        isLoading={isLoading}
      />
    </div>
  );
}
