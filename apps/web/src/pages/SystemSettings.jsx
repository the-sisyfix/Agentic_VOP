import { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../App.css'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

export default function SystemSettings() {
  const [siteName, setSiteName] = useState('Sisyfix')
  const [maintenanceMode, setMaintenanceMode] = useState(false)
  const [emailNotifications, setEmailNotifications] = useState(true)
  const [autoScan, setAutoScan] = useState(false)
  const [scanFrequency, setScanFrequency] = useState('24')
  const [maxScans, setMaxScans] = useState('5')

  // NVD Retry state
  const [nvdRetryLoading, setNvdRetryLoading] = useState(false)
  const [nvdRetryResult, setNvdRetryResult] = useState(null)
  const [nvdRetryError, setNvdRetryError] = useState(null)

  // Wire to backend when ready.
  const handleSave = () => {}

  const handleNvdRetry = async () => {
    setNvdRetryLoading(true)
    setNvdRetryResult(null)
    setNvdRetryError(null)
    try {
      const res = await fetch(`${API_URL}/admin/issues/retry_failed_nvd`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`)
      }
      const data = await res.json()
      setNvdRetryResult(data)
    } catch (err) {
      setNvdRetryError(err.message || 'Failed to retry NVD enrichment')
    } finally {
      setNvdRetryLoading(false)
    }
  }

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="dashboard-main">
          <div className="dashboard-header">
            <h1>System Settings</h1>
            <p className="dashboard-subtitle">Configure system-wide settings and preferences</p>
          </div>

          <div className="settings-container">
            {/* General Settings */}
            <div className="settings-section">
              <h2>General Settings</h2>
              <div className="settings-grid">
                <div className="settings-item">
                  <label className="settings-label">Site Name</label>
                  <input
                    type="text"
                    className="settings-input"
                    value={siteName}
                    onChange={(e) => setSiteName(e.target.value)}
                    placeholder="Sisyfix"
                  />
                </div>
                <div className="settings-item">
                  <label className="settings-label">API Endpoint</label>
                  <input
                    type="text"
                    className="settings-input"
                    value="http://127.0.0.1:8000"
                    disabled
                  />
                  <p className="settings-help">Backend API endpoint (read-only)</p>
                </div>
              </div>
            </div>

            {/* System Features */}
            <div className="settings-section">
              <h2>System Features</h2>
              <div className="settings-options">
                <label className="settings-checkbox">
                  <input
                    type="checkbox"
                    checked={maintenanceMode}
                    onChange={(e) => setMaintenanceMode(e.target.checked)}
                  />
                  <div className="checkbox-content">
                    <div className="checkbox-title">Enable Maintenance Mode</div>
                    <div className="checkbox-description">
                      Put the system in maintenance mode to prevent user access during updates
                    </div>
                  </div>
                </label>

                <label className="settings-checkbox">
                  <input
                    type="checkbox"
                    checked={emailNotifications}
                    onChange={(e) => setEmailNotifications(e.target.checked)}
                  />
                  <div className="checkbox-content">
                    <div className="checkbox-title">Enable Email Notifications</div>
                    <div className="checkbox-description">
                      Send email notifications for critical vulnerabilities and system alerts
                    </div>
                  </div>
                </label>

                <label className="settings-checkbox">
                  <input
                    type="checkbox"
                    checked={autoScan}
                    onChange={(e) => setAutoScan(e.target.checked)}
                    disabled
                  />
                  <div className="checkbox-content">
                    <div className="checkbox-title">Enable Automatic Vulnerability Scanning</div>
                    <div className="checkbox-description">
                      Automatically scan for vulnerabilities at scheduled intervals (Coming Soon)
                    </div>
                  </div>
                </label>
              </div>
            </div>

            {/* Scan Configuration */}
            <div className="settings-section">
              <h2>Scan Configuration</h2>
              <div className="settings-grid">
                <div className="settings-item">
                  <label className="settings-label">Scan Frequency (hours)</label>
                  <input
                    type="number"
                    className="settings-input"
                    value={scanFrequency}
                    onChange={(e) => setScanFrequency(e.target.value)}
                    min="1"
                    max="168"
                  />
                  <p className="settings-help">How often to run automated scans (1-168 hours)</p>
                </div>
                <div className="settings-item">
                  <label className="settings-label">Max Concurrent Scans</label>
                  <input
                    type="number"
                    className="settings-input"
                    value={maxScans}
                    onChange={(e) => setMaxScans(e.target.value)}
                    min="1"
                    max="20"
                  />
                  <p className="settings-help">Maximum number of scans to run simultaneously (1-20)</p>
                </div>
              </div>
            </div>

            {/* Data Maintenance */}
            <div className="settings-section">
              <h2>Data Maintenance</h2>
              <div className="settings-options">
                <div className="settings-maintenance-item">
                  <div className="checkbox-content">
                    <div className="checkbox-title">Retry Failed NVD Enrichment</div>
                    <div className="checkbox-description">
                      Re-fetch NVD data for issues that were missed due to API outages or
                      timeouts, then re-score affected issues with complete data.
                    </div>
                  </div>
                  <button
                    className="primary"
                    onClick={handleNvdRetry}
                    disabled={nvdRetryLoading}
                    style={{ marginTop: '12px', minWidth: '160px' }}
                  >
                    {nvdRetryLoading ? 'Retrying…' : 'Retry NVD Enrichment'}
                  </button>

                  {nvdRetryResult && (
                    <div className="settings-result" style={{
                      marginTop: '12px',
                      padding: '12px 16px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(16, 185, 129, 0.1)',
                      border: '1px solid rgba(16, 185, 129, 0.3)',
                      fontSize: '13px',
                      lineHeight: '1.6',
                    }}>
                      <strong style={{ color: '#10b981' }}>Completed</strong>
                      <div style={{ marginTop: '6px', color: '#e2e8f0' }}>
                        Issues found: {nvdRetryResult.issues_found} &nbsp;|&nbsp;
                        CVEs to lookup: {nvdRetryResult.cves_to_lookup}
                      </div>
                      <div style={{ color: '#e2e8f0' }}>
                        From cache: {nvdRetryResult.cves_from_cache} &nbsp;|&nbsp;
                        From NVD API: {nvdRetryResult.cves_from_nvd_api} &nbsp;|&nbsp;
                        Still missing: {nvdRetryResult.cves_still_missing}
                      </div>
                      <div style={{ color: '#e2e8f0' }}>
                        Issues re-scored: {nvdRetryResult.issues_rescored}
                      </div>
                    </div>
                  )}

                  {nvdRetryError && (
                    <div className="settings-result" style={{
                      marginTop: '12px',
                      padding: '12px 16px',
                      borderRadius: '8px',
                      backgroundColor: 'rgba(239, 68, 68, 0.1)',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      fontSize: '13px',
                      color: '#ef4444',
                    }}>
                      <strong>Error:</strong> {nvdRetryError}
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Save Button */}
            <div className="settings-actions">
              <button className="primary" onClick={handleSave}>
                Save All Settings
              </button>
            </div>
          </div>
        </main>
      </div>
    </>
  )
}
