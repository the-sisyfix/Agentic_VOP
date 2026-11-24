import React, { useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import '../styles/Settings.css'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

export default function Settings() {
  const [activeSection, setActiveSection] = useState('general')
  const [config, setConfig] = useState({})
  const [settingsSections] = useState([])

  // NVD Retry state
  const [nvdRetryLoading, setNvdRetryLoading] = useState(false)
  const [nvdRetryResult, setNvdRetryResult] = useState(null)
  const [nvdRetryError, setNvdRetryError] = useState(null)
  const handleToggle = (section, key) => {
    setConfig(prev => ({
      ...prev,
      [section]: {
        ...prev[section],
        [key]: !prev[section]?.[key]
      }
    }))
  }

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

  const getSectionIcon = (iconName) => {
    const icons = {
      settings: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="3"></circle>
          <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
        </svg>
      ),
      bell: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M18 8A6 6 0 0 0 6 8c0 7-3 9-3 9h18s-3-2-3-9"></path>
          <path d="M13.73 21a2 2 0 0 1-3.46 0"></path>
        </svg>
      ),
      search: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="11" cy="11" r="8"></circle>
          <path d="m21 21-4.35-4.35"></path>
        </svg>
      ),
      activity: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"></polyline>
        </svg>
      ),
      link: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"></path>
          <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"></path>
        </svg>
      ),
      database: (
        <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <ellipse cx="12" cy="5" rx="9" ry="3"></ellipse>
          <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"></path>
          <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"></path>
        </svg>
      )
    }
    return icons[iconName] || icons.settings
  }

  const renderSettingsContent = () => {
    switch (activeSection) {
      case 'general':
        return (
          <div className="settings-section">
            <h2>General Settings</h2>
            <p className="section-description">Organization and display preferences</p>

            <div className="settings-group">
              <div className="setting-item">
                <div className="setting-info">
                  <label>Organization Name</label>
                  <span className="setting-description">Your company or team name</span>
                </div>
                <input
                  type="text"
                  className="setting-input"
                  value={config.general?.organizationName ?? ''}
                  onChange={() => {}}
                />
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Timezone</label>
                  <span className="setting-description">Default timezone for reports and schedules</span>
                </div>
                <select className="setting-select" value={config.general?.timezone ?? ''} onChange={() => {}}>
                  <option>America/New_York</option>
                  <option>America/Los_Angeles</option>
                  <option>Europe/London</option>
                  <option>Asia/Tokyo</option>
                </select>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Date Format</label>
                  <span className="setting-description">How dates are displayed throughout the app</span>
                </div>
                <select className="setting-select" value={config.general?.dateFormat ?? ''} onChange={() => {}}>
                  <option>MM/DD/YYYY</option>
                  <option>DD/MM/YYYY</option>
                  <option>YYYY-MM-DD</option>
                </select>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Dark Mode</label>
                  <span className="setting-description">Use dark theme for the interface</span>
                </div>
                <button
                  className={`toggle-btn ${config.general?.darkMode ? 'active' : ''}`}
                  onClick={() => handleToggle('general', 'darkMode')}
                >
                  <span className="toggle-slider"></span>
                </button>
              </div>
            </div>
          </div>
        )

      case 'notifications':
        return (
          <div className="settings-section">
            <h2>Notification Settings</h2>
            <p className="section-description">Configure how and when you receive alerts</p>

            <div className="settings-group">
              <div className="setting-item">
                <div className="setting-info">
                  <label>Email Alerts</label>
                  <span className="setting-description">Receive notifications via email</span>
                </div>
                <button
                  className={`toggle-btn ${config.notifications?.emailAlerts ? 'active' : ''}`}
                  onClick={() => handleToggle('notifications', 'emailAlerts')}
                >
                  <span className="toggle-slider"></span>
                </button>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Slack Integration</label>
                  <span className="setting-description">Send alerts to Slack channels</span>
                </div>
                <button
                  className={`toggle-btn ${config.notifications?.slackIntegration ? 'active' : ''}`}
                  onClick={() => handleToggle('notifications', 'slackIntegration')}
                >
                  <span className="toggle-slider"></span>
                </button>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Critical Only</label>
                  <span className="setting-description">Only receive notifications for critical issues</span>
                </div>
                <button
                  className={`toggle-btn ${config.notifications?.criticalOnly ? 'active' : ''}`}
                  onClick={() => handleToggle('notifications', 'criticalOnly')}
                >
                  <span className="toggle-slider"></span>
                </button>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Digest Frequency</label>
                  <span className="setting-description">How often to receive summary emails</span>
                </div>
                <select className="setting-select" value={config.notifications?.digestFrequency ?? ''} onChange={() => {}}>
                  <option>Hourly</option>
                  <option>Daily</option>
                  <option>Weekly</option>
                  <option>Never</option>
                </select>
              </div>
            </div>
          </div>
        )

      case 'scanning':
        return (
          <div className="settings-section">
            <h2>Scanning Configuration</h2>
            <p className="section-description">Configure vulnerability scanning settings</p>

            <div className="settings-group">
              <div className="setting-item">
                <div className="setting-info">
                  <label>Auto Scan</label>
                  <span className="setting-description">Automatically run scans on schedule</span>
                </div>
                <button
                  className={`toggle-btn ${config.scanning?.autoScan ? 'active' : ''}`}
                  onClick={() => handleToggle('scanning', 'autoScan')}
                >
                  <span className="toggle-slider"></span>
                </button>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Scan Frequency</label>
                  <span className="setting-description">How often to run automated scans</span>
                </div>
                <select className="setting-select" value={config.scanning?.scanFrequency ?? ''} onChange={() => {}}>
                  <option>Hourly</option>
                  <option>Daily</option>
                  <option>Weekly</option>
                  <option>Monthly</option>
                </select>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Scan Window</label>
                  <span className="setting-description">Preferred time window for scans</span>
                </div>
                <input
                  type="text"
                  className="setting-input"
                  value={config.scanning?.scanWindow ?? ''}
                  onChange={() => {}}
                />
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Exclude Weekends</label>
                  <span className="setting-description">Skip scanning on weekends</span>
                </div>
                <button
                  className={`toggle-btn ${config.scanning?.excludeWeekends ? 'active' : ''}`}
                  onClick={() => handleToggle('scanning', 'excludeWeekends')}
                >
                  <span className="toggle-slider"></span>
                </button>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Parallel Scans</label>
                  <span className="setting-description">Maximum concurrent scan operations</span>
                </div>
                <select className="setting-select" value={config.scanning?.parallelScans ?? ''} onChange={() => {}}>
                  <option value="1">1</option>
                  <option value="3">3</option>
                  <option value="5">5</option>
                  <option value="10">10</option>
                </select>
              </div>
            </div>
          </div>
        )

      case 'risk':
        return (
          <div className="settings-section">
            <h2>Risk Scoring</h2>
            <p className="section-description">Configure risk calculation parameters</p>

            <div className="settings-group">
              <div className="setting-item">
                <div className="setting-info">
                  <label>Scoring Model</label>
                  <span className="setting-description">Base model for risk calculations</span>
                </div>
                <select className="setting-select" value={config.risk?.scoringModel ?? ''} onChange={() => {}}>
                  <option>CVSS Only</option>
                  <option>CVSS + Context</option>
                  <option>Custom Weighted</option>
                </select>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Auto Reprioritize</label>
                  <span className="setting-description">Automatically update priorities when context changes</span>
                </div>
                <button
                  className={`toggle-btn ${config.risk?.autoReprioritize ? 'active' : ''}`}
                  onClick={() => handleToggle('risk', 'autoReprioritize')}
                >
                  <span className="toggle-slider"></span>
                </button>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Asset Criticality Weight</label>
                  <span className="setting-description">How much asset criticality affects risk score</span>
                </div>
                <div className="slider-container">
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={(config.risk?.assetCriticalityWeight ?? 0) * 100}
                    className="setting-slider"
                    onChange={() => {}}
                  />
                  <span className="slider-value">{Math.round((config.risk?.assetCriticalityWeight ?? 0) * 100)}%</span>
                </div>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Exploitability Weight</label>
                  <span className="setting-description">How much exploitability affects risk score</span>
                </div>
                <div className="slider-container">
                  <input
                    type="range"
                    min="0"
                    max="100"
                    value={(config.risk?.exploitabilityWeight ?? 0) * 100}
                    className="setting-slider"
                    onChange={() => {}}
                  />
                  <span className="slider-value">{Math.round((config.risk?.exploitabilityWeight ?? 0) * 100)}%</span>
                </div>
              </div>
            </div>
          </div>
        )

      case 'retention':
        return (
          <div className="settings-section">
            <h2>Data Retention</h2>
            <p className="section-description">Configure data storage policies</p>

            <div className="settings-group">
              <div className="setting-item">
                <div className="setting-info">
                  <label>Vulnerability Data</label>
                  <span className="setting-description">How long to keep vulnerability records</span>
                </div>
                <select className="setting-select" value={config.retention?.vulnerabilityData ?? ''} onChange={() => {}}>
                  <option>6 months</option>
                  <option>1 year</option>
                  <option>2 years</option>
                  <option>5 years</option>
                </select>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Scan Results</label>
                  <span className="setting-description">How long to keep scan result history</span>
                </div>
                <select className="setting-select" value={config.retention?.scanResults ?? ''} onChange={() => {}}>
                  <option>3 months</option>
                  <option>6 months</option>
                  <option>1 year</option>
                  <option>2 years</option>
                </select>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Audit Logs</label>
                  <span className="setting-description">How long to keep audit trail records</span>
                </div>
                <select className="setting-select" value={config.retention?.auditLogs ?? ''} onChange={() => {}}>
                  <option>1 year</option>
                  <option>3 years</option>
                  <option>5 years</option>
                  <option>7 years</option>
                </select>
              </div>
              <div className="setting-item">
                <div className="setting-info">
                  <label>Reports</label>
                  <span className="setting-description">How long to keep generated reports</span>
                </div>
                <select className="setting-select" value={config.retention?.reports ?? ''} onChange={() => {}}>
                  <option>1 year</option>
                  <option>2 years</option>
                  <option>3 years</option>
                  <option>5 years</option>
                </select>
              </div>
            </div>
          </div>
        )

      default:
        return null
    }
  }

  return (
    <div className="settings-page-wrapper">
      <Topbar />
      <div className="settings-layout">
        <Sidebar />
        <main className="settings-main">
          <div className="settings-header">
            <h1>Settings</h1>
            <p className="settings-subtitle">Configure your Sisyfix platform</p>
          </div>

          <div className="settings-content">
            {/* Settings Navigation */}
            <div className="settings-nav">
              {settingsSections.map((section) => (
                <button
                  key={section.id}
                  className={`settings-nav-item ${activeSection === section.id ? 'active' : ''}`}
                  onClick={() => setActiveSection(section.id)}
                >
                  <span className="nav-icon">{getSectionIcon(section.icon)}</span>
                  <div className="nav-text">
                    <span className="nav-name">{section.name}</span>
                    <span className="nav-description">{section.description}</span>
                  </div>
                </button>
              ))}
            </div>

            {/* Settings Content */}
            <div className="settings-panel">
              {renderSettingsContent()}

              {/* Data Maintenance — always visible */}
              <div className="settings-section">
                <h2>Data Maintenance</h2>
                <p className="section-description">Manual actions for data recovery and re-enrichment</p>

                <div className="settings-group">
                  <div className="setting-item" style={{ flexDirection: 'column', alignItems: 'flex-start' }}>
                    <div className="setting-info">
                      <label>Retry Failed NVD Enrichment</label>
                      <span className="setting-description">
                        Re-fetch NVD data for issues missed due to API outages or timeouts,
                        then re-score affected issues with complete data.
                      </span>
                    </div>
                    <button
                      className="btn-primary"
                      onClick={handleNvdRetry}
                      disabled={nvdRetryLoading}
                      style={{ marginTop: '12px' }}
                    >
                      {nvdRetryLoading ? 'Retrying…' : 'Retry NVD Enrichment'}
                    </button>

                    {nvdRetryResult && (
                      <div style={{
                        marginTop: '12px',
                        padding: '12px 16px',
                        borderRadius: '8px',
                        backgroundColor: 'rgba(16, 185, 129, 0.1)',
                        border: '1px solid rgba(16, 185, 129, 0.3)',
                        fontSize: '13px',
                        lineHeight: '1.6',
                        width: '100%',
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
                      <div style={{
                        marginTop: '12px',
                        padding: '12px 16px',
                        borderRadius: '8px',
                        backgroundColor: 'rgba(239, 68, 68, 0.1)',
                        border: '1px solid rgba(239, 68, 68, 0.3)',
                        fontSize: '13px',
                        color: '#ef4444',
                        width: '100%',
                      }}>
                        <strong>Error:</strong> {nvdRetryError}
                      </div>
                    )}
                  </div>
                </div>
              </div>

              <div className="settings-footer">
                <button className="btn-secondary">
                  Cancel
                </button>
                <button className="btn-primary">
                  Save Changes
                </button>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  )
}
