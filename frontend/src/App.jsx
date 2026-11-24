import React, { useState, useEffect, useCallback } from 'react';
import { AlertCircle, WifiOff, Terminal, RefreshCw } from 'lucide-react';
import { api } from './services/api';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import SimulationModal from './components/SimulationModal';
import DashboardPage from './pages/DashboardPage';
import TrafficPage from './pages/TrafficPage';
import AlertsPage from './pages/AlertsPage';
import UploadPage from './pages/UploadPage';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [health, setHealth] = useState(null);
  const [stats, setStats] = useState(null);
  const [recentAlerts, setRecentAlerts] = useState([]);
  const [isOnline, setIsOnline] = useState(true);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isSimulateOpen, setIsSimulateOpen] = useState(false);
  const [isSimulating, setIsSimulating] = useState(false);
  const [errorBanner, setErrorBanner] = useState(null);

  // Fetch telemetry from backend
  const fetchTelemetry = useCallback(async () => {
    setIsRefreshing(true);
    setErrorBanner(null);

    try {
      // 1. Health check
      const healthData = await api.getHealth();
      setHealth(healthData);
      setIsOnline(true);

      // 2. Dashboard summary statistics
      const statsData = await api.getStats();
      setStats(statsData);

      // 3. Top recent alerts for quick preview
      const alertsData = await api.getAlerts({ limit: 10, offset: 0 });
      setRecentAlerts(alertsData.items || []);
    } catch (err) {
      setIsOnline(false);
      setErrorBanner(err.message || 'Unable to connect to NIDS backend server.');
    } finally {
      setIsRefreshing(false);
    }
  }, []);

  // Poll health and telemetry on mount and every 15 seconds
  useEffect(() => {
    fetchTelemetry();
    const interval = setInterval(() => {
      fetchTelemetry();
    }, 15000);
    return () => clearInterval(interval);
  }, [fetchTelemetry]);

  // Handle traffic simulation trigger
  const handleSimulate = async (params) => {
    setIsSimulating(true);
    try {
      const response = await api.simulateTraffic(params);
      await fetchTelemetry(); // Refresh metrics immediately
      return response;
    } finally {
      setIsSimulating(false);
    }
  };

  return (
    <div className="flex flex-col h-screen bg-[#0B0F19] text-gray-100 overflow-hidden font-sans">
      {/* Top Navbar */}
      <Navbar
        health={health}
        isOnline={isOnline}
        isRefreshing={isRefreshing}
        onRefresh={fetchTelemetry}
        onOpenSimulate={() => setIsSimulateOpen(true)}
      />

      {/* Offline Alert Banner */}
      {!isOnline && (
        <div className="bg-rose-950/80 border-b border-rose-500/40 px-4 py-2 text-xs flex flex-wrap items-center justify-between gap-2 text-rose-300 font-mono">
          <div className="flex items-center space-x-2">
            <WifiOff className="w-4 h-4 text-rose-400 flex-shrink-0" />
            <span>
              <strong>Disconnected from NIDS backend:</strong> {errorBanner || 'Cannot reach http://127.0.0.1:8000.'}
            </span>
          </div>
          <div className="flex items-center space-x-3 text-[11px]">
            <span className="text-gray-400">Run:</span>
            <code className="px-2 py-0.5 rounded bg-black/60 text-cyan-300 border border-gray-800">
              python -m uvicorn backend.app.main:app
            </code>
            <button
              onClick={fetchTelemetry}
              className="px-2.5 py-0.5 rounded bg-rose-900/60 hover:bg-rose-800 text-white transition flex items-center space-x-1"
            >
              <RefreshCw className="w-3 h-3" />
              <span>Retry</span>
            </button>
          </div>
        </div>
      )}

      {/* Main Container: Sidebar + Content */}
      <div className="flex flex-1 overflow-hidden">
        {/* Sidebar */}
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          alertsCount={stats?.total_alerts || 0}
        />

        {/* Dynamic Page Content */}
        <main className="flex-1 overflow-y-auto p-4 md:p-6 lg:p-8">
          {activeTab === 'dashboard' && (
            <DashboardPage
              stats={stats}
              recentAlerts={recentAlerts}
              onNavigateToAlerts={() => setActiveTab('alerts')}
            />
          )}

          {activeTab === 'traffic' && <TrafficPage />}

          {activeTab === 'alerts' && <AlertsPage />}

          {activeTab === 'upload' && (
            <UploadPage
              onUploadSuccess={() => {
                fetchTelemetry();
              }}
            />
          )}
        </main>
      </div>

      {/* Simulation Modal */}
      <SimulationModal
        isOpen={isSimulateOpen}
        onClose={() => setIsSimulateOpen(false)}
        onSimulate={handleSimulate}
        isSimulating={isSimulating}
      />
    </div>
  );
}
