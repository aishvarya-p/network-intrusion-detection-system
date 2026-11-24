/**
 * Centralized API Client for NIDS Backend.
 * Connects to FastAPI backend at http://127.0.0.1:8000 (configurable via VITE_API_BASE_URL).
 */

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

async function request(endpoint, options = {}) {
  const url = `${API_BASE_URL}${endpoint}`;
  try {
    const response = await fetch(url, options);

    if (!response.ok) {
      let errorMessage = `HTTP error ${response.status}: ${response.statusText}`;
      try {
        const errorData = await response.json();
        if (errorData && errorData.detail) {
          errorMessage = typeof errorData.detail === 'string'
            ? errorData.detail
            : JSON.stringify(errorData.detail);
        } else if (errorData && errorData.message) {
          errorMessage = errorData.message;
        }
      } catch {
        // Fallback to response.statusText if response is not JSON
      }
      throw new Error(errorMessage);
    }

    return await response.json();
  } catch (err) {
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      throw new Error(
        `Unable to connect to NIDS backend at ${API_BASE_URL}. Ensure the FastAPI server is running.`
      );
    }
    throw err;
  }
}

export const api = {
  /** Check system and model health status */
  getHealth: () => request('/health'),

  /** Get aggregated SOC dashboard metrics */
  getStats: () => request('/stats'),

  /** Get paginated and filtered network flow records */
  getTraffic: ({ limit = 50, offset = 0, protocol = null, isSuspicious = null } = {}) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (protocol && protocol !== 'ALL') {
      params.append('protocol', protocol);
    }
    if (isSuspicious !== null && isSuspicious !== 'ALL') {
      params.append('is_suspicious', isSuspicious === 'true' || isSuspicious === true ? 'true' : 'false');
    }
    return request(`/traffic?${params.toString()}`);
  },

  /** Get paginated and filtered security alert records */
  getAlerts: ({ limit = 50, offset = 0, severity = null, isResolved = null } = {}) => {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (severity && severity !== 'ALL') {
      params.append('severity', severity);
    }
    if (isResolved !== null && isResolved !== 'ALL') {
      params.append('is_resolved', isResolved === 'true' || isResolved === true ? 'true' : 'false');
    }
    return request(`/alerts?${params.toString()}`);
  },

  /** Simulate a batch of synthetic network traffic */
  simulateTraffic: ({ totalFlows = 50, anomalyRatio = 0.15, attackTypes = null } = {}) => {
    return request('/simulate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        total_flows: totalFlows,
        anomaly_ratio: anomalyRatio,
        attack_types: attackTypes,
      }),
    });
  },

  /** Upload a CSV network flow dataset for inspection */
  uploadCsv: (file) => {
    const formData = new FormData();
    formData.append('file', file);
    return request('/upload-csv', {
      method: 'POST',
      body: formData,
    });
  },
};
