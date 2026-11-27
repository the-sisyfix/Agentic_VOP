import { useState, useMemo, useEffect } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import ColumnToggle, { useColumnVisibility } from '../components/ColumnToggle'
import Tooltip from '../components/Tooltip'
import '../styles/Assets.css'
import MultiSelectFilter from '../components/MultiSelectFilter'
import { useNavigate } from 'react-router-dom'
import { useAssetsData, fetchIssuesForAsset } from '../hooks/useAssetsData'

const assetsColumns = [
  { key: 'asset_id', label: 'Asset ID' },
  { key: 'type', label: 'Type' },
  { key: 'hostname', label: 'Asset' },
  { key: 'asset_criticality', label: 'Criticality' },
  { key: 'environment', label: 'Environment' },
  { key: 'it_owner', label: 'Contact' },
  { key: 'data_classification', label: 'Classification' },
]

export default function Assets() {
  const { assets, loading } = useAssetsData()
  const isColdLoading = loading && assets.length === 0
  const [assetIssues, setAssetIssues] = useState([])
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedFilter, setSelectedFilter] = useState('All')
  const [currentPage, setCurrentPage] = useState(1)
  const [selectedAsset, setSelectedAsset] = useState(null)
  const [selectedIssue, setSelectedIssue] = useState(null)
  const [assetTypes, setAssetTypes] = useState([])
  const [sortByRisk, setSortByRisk] = useState(true)

  const itemsPerPage = 10
  const navigate = useNavigate()

  // When an asset is selected, fetch its issues from the database
  useEffect(() => {
    if (selectedAsset) {
      setSortByRisk(true)
      fetchIssuesForAsset(selectedAsset).then(setAssetIssues)
    } else {
      setAssetIssues([])
    }
  }, [selectedAsset])

  const assetTypeOptions = useMemo(() => {
    const map = new Map()
    assets.forEach(item => {
      const key = item.type
      if (!key) return
      if (!map.has(key)) {
        map.set(key, { key, label: key.replace(/_/g, ' '), count: 0 })
      }
      map.get(key).count += 1
    })
    return Array.from(map.values())
  }, [assets])

  const { visibleColumns, setVisibleColumns, isVisible } = useColumnVisibility(assets, [], [])

  const filterCounts = {
    critical: assets.filter(a => a.asset_criticality === 'Critical').length,
    high: assets.filter(a => a.asset_criticality === 'High').length,
    medium: assets.filter(a => a.asset_criticality === 'Medium').length,
    low: assets.filter(a => a.asset_criticality === 'Low').length,
    total: assets.length
  }

  const filteredAssets = assets.filter(asset => {
    const matchesFilter = selectedFilter === 'All' || asset.asset_criticality === selectedFilter
    const matchesSearch = searchTerm === '' ||
      asset.asset_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.hostname?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      asset.application_name?.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesAssetType = assetTypes.length === 0 || assetTypes.includes(asset.type)
    return matchesFilter && matchesSearch && matchesAssetType
  })

  const totalPages = Math.ceil(filteredAssets.length / itemsPerPage)
  const startIndex = (currentPage - 1) * itemsPerPage
  const paginatedAssets = filteredAssets.slice(startIndex, startIndex + itemsPerPage)

  const getCriticalityClass = (criticality) => {
    if (criticality === 'Critical') return 'critical'
    if (criticality === 'High') return 'high'
    if (criticality === 'Medium') return 'medium'
    return 'low'
  }

  const getEnvironmentClass = (env) => {
    if (env === 'Production') return 'production'
    if (env === 'Staging') return 'staging'
    if (env === 'QA') return 'qa'
    return 'development'
  }

  const getClassificationClass = (classification) => {
    if (classification === 'Restricted') return 'restricted'
    if (classification === 'Confidential') return 'confidential'
    if (classification === 'Internal') return 'internal'
    return 'public'
  }

  const getRiskScoreClass = (score) => {
    if (score >= 90) return 'critical'
    if (score >= 70) return 'high'
    if (score >= 40) return 'medium'
    return 'low'
  }

  const getSeverityClass = (severity) => {
    if (!severity) return 'low'
    const sev = severity.toUpperCase()
    if (sev === 'CRITICAL') return 'critical'
    if (sev === 'HIGH') return 'high'
    if (sev === 'MEDIUM') return 'medium'
    return 'low'
  }

  const handleFilterChange = (filter) => {
    setSelectedFilter(filter)
    setCurrentPage(1)
  }

  const handleRowClick = (asset) => {
    setSelectedAsset(asset)
    setSelectedIssue(null)
    setAssetIssues([])
  }

  const handleIssueClick = (issue, e) => {
    e.stopPropagation()
    setSelectedIssue(issue)
  }

  const closeIssuesCard = () => {
    setSelectedAsset(null)
    setSelectedIssue(null)
  }

  const closeIssueDetail = () => {
    setSelectedIssue(null)
  }

  const handleExportCSV = () => {
    // Wire to real export endpoint when ready
  }

  return (
    <div className="assets-page-wrapper">
      <Topbar />
      <div className="assets-layout">
        <Sidebar />
        <main className="assets-main">
          <div className="assets-header">
            <h1>Assets</h1>
            <p className="assets-subtitle">Manage and monitor your organization's infrastructure assets</p>
          </div>

          <div className="assets-card">
            <div className="assets-filters">
              <div className="assets-filter-chips">
                <button
                  className={`assets-chip ${selectedFilter === 'All' ? 'active' : ''}`}
                  onClick={() => handleFilterChange('All')}
                >
                  All ({filterCounts.total})
                </button>
              </div>

              <div className="assets-toolbar">
                <div className="assets-search">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                  </svg>
                  <input
                    type="text"
                    placeholder="Search by asset ID, hostname, or application name..."
                    value={searchTerm}
                    onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                  />
                </div>

                <div className="toolbar-actions">
                  <button className="toolbar-btn" onClick={handleExportCSV} title="Export CSV">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                      <polyline points="7 10 12 15 17 10"></polyline>
                      <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                  </button>
                </div>

                <ColumnToggle
                  data={assets}
                  columns={assetsColumns}
                  visibleColumns={visibleColumns}
                  onChange={setVisibleColumns}
                />

                <MultiSelectFilter
                  title="Asset Type"
                  options={assetTypeOptions}
                  value={assetTypes}
                  onChange={(types) => {
                    setAssetTypes(types)
                    setCurrentPage(1)
                  }}
                />
              </div>
            </div>

            <div className="assets-table-container">
              <table className="assets-table">
                <thead>
                  <tr>
                    {isVisible('asset_id') && <th>ASSET ID</th>}
                    {isVisible('type') && <th>TYPE</th>}
                    {isVisible('hostname') && <th>ASSET</th>}
                    {isVisible('asset_criticality') && <th>CRITICALITY</th>}
                    {isVisible('environment') && <th>ENVIRONMENT</th>}
                    {isVisible('it_owner') && <th>CONTACT</th>}
                    {isVisible('data_classification') && <th>CLASSIFICATION</th>}
                    <th className="th-view">VIEW</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedAssets.length === 0 ? (
                    isColdLoading ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <tr key={`skeleton-${i}`} className="assets-skeleton-row">
                          <td colSpan="100">
                            <span className="skeleton-block" style={{ height: 14, width: '95%' }} />
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="100" className="assets-empty">
                          No assets found matching your criteria
                        </td>
                      </tr>
                    )
                  ) : (
                    paginatedAssets.map((asset) => (
                      <tr
                        key={asset.asset_id}
                        className={`assets-row-clickable ${selectedAsset?.asset_id === asset.asset_id ? 'selected' : ''}`}
                        onClick={() => handleRowClick(asset)}
                      >
                        {isVisible('asset_id') && (
                          <td>
                            <span className="assets-id-badge">{asset.asset_id}</span>
                          </td>
                        )}
                        {isVisible('type') && (
                          <td>
                            <span className="assets-type">{asset.type}</span>
                          </td>
                        )}
                        {isVisible('hostname') && (
                          <td>
                            <div className="combined-cell">
                              <span className="combined-primary">{asset.hostname}</span>
                              <span className="combined-secondary">{asset.application_name}</span>
                            </div>
                          </td>
                        )}
                        {isVisible('asset_criticality') && (
                          <td>
                            <span className={`assets-criticality ${getCriticalityClass(asset.asset_criticality)}`}>
                              {asset.asset_criticality}
                            </span>
                          </td>
                        )}
                        {isVisible('environment') && (
                          <td>
                            <span className={`assets-environment ${getEnvironmentClass(asset.environment)}`}>
                              {asset.environment}
                            </span>
                          </td>
                        )}
                        {isVisible('it_owner') && (
                          <td>
                            <div className="combined-cell">
                              <span className="combined-primary">{asset.it_owner}</span>
                              <span className="combined-secondary">{asset.contact_email}</span>
                            </div>
                          </td>
                        )}
                        {isVisible('data_classification') && (
                          <td>
                            <span className={`assets-classification ${getClassificationClass(asset.data_classification)}`}>
                              {asset.data_classification}
                            </span>
                          </td>
                        )}
                        <td className="assets-cell-view">
                          <span className="row-click-indicator" title="View Issues">
                            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                              <polyline points="9 18 15 12 9 6"></polyline>
                            </svg>
                          </span>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="assets-footer">
              <span className="assets-count">
                Showing {startIndex + 1}-{Math.min(startIndex + itemsPerPage, filteredAssets.length)} of {filteredAssets.length} assets
              </span>

              {totalPages > 1 && (
                <div className="assets-pagination">
                  <button
                    className="pagination-btn"
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                  </button>

                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                    <button
                      key={page}
                      className={`pagination-btn ${currentPage === page ? 'active' : ''}`}
                      onClick={() => setCurrentPage(page)}
                    >
                      {page}
                    </button>
                  ))}

                  <button
                    className="pagination-btn"
                    onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
                    disabled={currentPage === totalPages}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="9 18 15 12 9 6"></polyline>
                    </svg>
                  </button>
                </div>
              )}
            </div>
          </div>
        </main>

        {/* Issues Panel - Shows when asset row is clicked */}
        {selectedAsset && (
          <>
            <div className="asset-overlay" onClick={closeIssuesCard}></div>
            <div className="asset-issues-panel">
              <div className="issues-panel-header">
                <div className="issues-panel-title">
                  <h3 className="asset-title">{selectedAsset.hostname}</h3>

                  <div className="issues-panel-meta">
                    <span className="issues-panel-count">
                      {assetIssues.length} Issues
                    </span>

                    <button
                      className={`risk-toggle ${sortByRisk ? "active" : ""}`}
                      onClick={() => setSortByRisk(prev => !prev)}
                      title="Sort by Risk"
                    >
                      R
                    </button>
                  </div>
                </div>
                <button className="issues-panel-close" onClick={closeIssuesCard}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                  </svg>
                </button>
              </div>

              <div className="issues-panel-list">
                {[...assetIssues]
                  .sort((a, b) => {
                    if (sortByRisk) {
                      return (b.derived_risk || 0) - (a.derived_risk || 0);
                    }

                    const criticalityOrder = {
                      critical: 4,
                      high: 3,
                      medium: 2,
                      low: 1,
                    };

                    return (
                      (criticalityOrder[b.severity?.toLowerCase()] || 0) -
                      (criticalityOrder[a.severity?.toLowerCase()] || 0)
                    );
                  })
                  .map((issue) => (
                    <div
                      key={issue.issue_id}
                      className={`issue-panel-item ${selectedIssue?.issue_id === issue.issue_id ? 'selected' : ''}`}
                      onClick={(e) => handleIssueClick(issue, e)}
                    >
                      <div className="issue-panel-row">
                        <span className="issue-panel-id">{issue.issue_id}</span>
                        <span className={`issue-panel-severity ${getSeverityClass(issue.severity)}`}>
                          {issue.severity}
                        </span>
                      </div>
                      <div className="issue-panel-cve">{issue.cve_id}</div>
                      <div className="issue-panel-desc">{issue.description}</div>
                      <div className="issue-panel-meta">
                        <span className="issue-panel-risk">
                          Risk: <strong>{issue.derived_risk}</strong>
                        </span>
                        <span className="issue-panel-source">{issue.source}</span>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          </>
        )}

        {/* Issue Detail Drawer - Shows when issue is clicked */}
        {selectedIssue && (
          <div className="issue-detail-overlay" onClick={closeIssueDetail}>
            <div className="issue-detail-drawer" onClick={(e) => e.stopPropagation()}>
              <div className="issue-drawer-header">
                <div className="issue-drawer-title">
                  <span className="issue-drawer-id">{selectedIssue.issue_id}</span>
                  <span className={`issue-drawer-severity ${getSeverityClass(selectedIssue.severity)}`}>
                    {selectedIssue.severity}
                  </span>
                </div>
                <button className="issue-drawer-close" onClick={closeIssueDetail}>
                  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <line x1="18" y1="6" x2="6" y2="18"></line>
                    <line x1="6" y1="6" x2="18" y2="18"></line>
                  </svg>
                </button>
              </div>

              <div className="issue-drawer-content">
                <div className="issue-drawer-section">
                  <h4>CVE Information</h4>
                  <div className="issue-drawer-cve">{selectedIssue.cve_id}</div>
                </div>

                <div className="issue-drawer-section">
                  <h4>Description</h4>
                  <p className="issue-drawer-desc">{selectedIssue.description}</p>
                </div>

                <div className="issue-drawer-grid">
                  <div className="issue-drawer-item">
                    <span className="issue-drawer-label">Asset</span>
                    <span className="issue-drawer-value">{selectedIssue.asset_name}</span>
                  </div>
                  <div className="issue-drawer-item">
                    <span className="issue-drawer-label">Asset Type</span>
                    <span className="issue-drawer-value">{selectedIssue.asset_type}</span>
                  </div>
                  <div className="issue-drawer-item">
                    <span className="issue-drawer-label">Derived Risk</span>
                    <Tooltip content="Derived by Sisy">
                      <span className={`issue-drawer-risk ${getRiskScoreClass(selectedIssue.derived_risk)}`}>
                        {selectedIssue.derived_risk}
                      </span>
                    </Tooltip>
                  </div>
                  <div className="issue-drawer-item">
                    <span className="issue-drawer-label">Threat Vector</span>
                    <span className="issue-drawer-value">{selectedIssue.threat_vector}</span>
                  </div>
                  <div className="issue-drawer-item">
                    <span className="issue-drawer-label">Remediable</span>
                    <span className={`issue-drawer-remediable ${selectedIssue.remediable ? 'yes' : 'no'}`}>
                      {selectedIssue.remediable ? 'Yes' : 'No'}
                    </span>
                  </div>
                  <div className="issue-drawer-item">
                    <span className="issue-drawer-label">Source</span>
                    <span className="issue-drawer-value">{selectedIssue.source}</span>
                  </div>
                </div>

                <div className="issue-drawer-actions">
                  <button
                    className="issue-drawer-btn primary"
                    onClick={() => {
                      navigate(`/issues?issue_id=${selectedIssue.issue_id}`, {
                        state: { issue: selectedIssue }
                      })
                    }}
                  >
                    View in Issues Page
                  </button>

                  <button
                    className="issue-drawer-btn secondary"
                    onClick={() => {
                      navigate(`/remediation?issue_id=${selectedIssue.issue_id}`, {
                        state: { issue: selectedIssue }
                      })
                    }}
                  >
                    View Remediation
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}