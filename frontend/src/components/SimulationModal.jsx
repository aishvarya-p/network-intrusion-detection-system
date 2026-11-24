import React, { useState } from 'react';
import { Zap, X, ShieldAlert, CheckCircle2, AlertCircle } from 'lucide-react';

export default function SimulationModal({ isOpen, onClose, onSimulate, isSimulating }) {
  const [totalFlows, setTotalFlows] = useState(50);
  const [anomalyRatio, setAnomalyRatio] = useState(0.20);
  const [selectedAttacks, setSelectedAttacks] = useState(['PORT_SCAN', 'SYN_FLOOD', 'DATA_EXFILTRATION']);
  const [resultSummary, setResultSummary] = useState(null);
  const [errorMessage, setErrorMessage] = useState(null);

  if (!isOpen) return null;

  const handleToggleAttack = (atk) => {
    if (selectedAttacks.includes(atk)) {
      if (selectedAttacks.length > 1) {
        setSelectedAttacks(selectedAttacks.filter((a) => a !== atk));
      }
    } else {
      setSelectedAttacks([...selectedAttacks, atk]);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage(null);
    setResultSummary(null);

    try {
      const res = await onSimulate({
        totalFlows: Number(totalFlows),
        anomalyRatio: Number(anomalyRatio),
        attackTypes: selectedAttacks,
      });
      setResultSummary(res);
    } catch (err) {
      setErrorMessage(err.message || 'Simulation failed');
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-lg rounded-2xl bg-[#111827] border border-gray-800 shadow-2xl p-6 space-y-5">
        {/* Header */}
        <div className="flex items-center justify-between border-b border-gray-800 pb-4">
          <div className="flex items-center space-x-2 text-cyan-400">
            <Zap className="w-5 h-5" />
            <h3 className="text-base font-semibold text-white">Simulate Network Traffic Batch</h3>
          </div>
          <button
            onClick={onClose}
            className="p-1 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-mono text-gray-300 uppercase mb-1.5">
              Total Flows to Generate: <span className="text-cyan-400 font-bold">{totalFlows}</span>
            </label>
            <input
              type="range"
              min="10"
              max="500"
              step="10"
              value={totalFlows}
              onChange={(e) => setTotalFlows(Number(e.target.value))}
              className="w-full accent-cyan-500 bg-gray-800 rounded-lg cursor-pointer"
            />
            <div className="flex justify-between text-[11px] text-gray-500 font-mono mt-1">
              <span>10 flows</span>
              <span>250 flows</span>
              <span>500 flows</span>
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-gray-300 uppercase mb-1.5">
              Anomaly Proportion: <span className="text-rose-400 font-bold">{Math.round(anomalyRatio * 100)}%</span>
            </label>
            <input
              type="range"
              min="0.0"
              max="0.5"
              step="0.05"
              value={anomalyRatio}
              onChange={(e) => setAnomalyRatio(Number(e.target.value))}
              className="w-full accent-rose-500 bg-gray-800 rounded-lg cursor-pointer"
            />
            <div className="flex justify-between text-[11px] text-gray-500 font-mono mt-1">
              <span>0% (Clean)</span>
              <span>25%</span>
              <span>50% (High Attack)</span>
            </div>
          </div>

          <div>
            <label className="block text-xs font-mono text-gray-300 uppercase mb-2">
              Simulated Threat Patterns
            </label>
            <div className="grid grid-cols-3 gap-2">
              {[
                { id: 'PORT_SCAN', label: 'Port Scan' },
                { id: 'SYN_FLOOD', label: 'SYN Flood' },
                { id: 'DATA_EXFILTRATION', label: 'Exfiltration' },
              ].map((atk) => {
                const isSelected = selectedAttacks.includes(atk.id);
                return (
                  <button
                    key={atk.id}
                    type="button"
                    onClick={() => handleToggleAttack(atk.id)}
                    className={`px-3 py-2 rounded-lg text-xs font-medium border transition ${
                      isSelected
                        ? 'bg-cyan-950/70 text-cyan-300 border-cyan-500/50 shadow-sm'
                        : 'bg-gray-900 text-gray-500 border-gray-800 hover:text-gray-300'
                    }`}
                  >
                    {atk.label}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Feedback & Results */}
          {errorMessage && (
            <div className="p-3 rounded-lg bg-rose-950/40 border border-rose-500/30 text-rose-400 text-xs flex items-center space-x-2">
              <AlertCircle className="w-4 h-4 flex-shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}

          {resultSummary && (
            <div className="p-3.5 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-emerald-300 text-xs space-y-1 font-mono">
              <div className="flex items-center space-x-1.5 font-semibold text-emerald-400">
                <CheckCircle2 className="w-4 h-4" />
                <span>Simulation Complete</span>
              </div>
              <div className="text-[11px] text-gray-300">
                Generated: <strong className="text-white">{resultSummary.total_generated}</strong> flows (Normal: {resultSummary.normal_count}, Suspicious: {resultSummary.suspicious_count}, Alerts: {resultSummary.alerts_generated})
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="pt-2 flex justify-end space-x-2">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 rounded-lg bg-gray-800 hover:bg-gray-700 text-gray-300 text-xs font-medium transition"
            >
              Close
            </button>
            <button
              type="submit"
              disabled={isSimulating}
              className="flex items-center space-x-1.5 px-4 py-2 rounded-lg bg-cyan-600 hover:bg-cyan-500 text-white text-xs font-medium transition disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${isSimulating ? 'animate-bounce' : ''}`} />
              <span>{isSimulating ? 'Generating & Analyzing...' : 'Run Simulation'}</span>
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
