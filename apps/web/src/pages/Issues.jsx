import { useState, useCallback, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import ColumnToggle from '../components/ColumnToggle'
import '../styles/Issues.css'
import SeverityFilter from '../components/SeverityFilter'
import { useIssuesData } from '../hooks/useIssuesData'

// Approx vertical overhead above the table body: topbar + page header +
// filters/toolbar + pagination footer = ~360px on most layouts.
// Each table row is ~46px in the current density. We compute how many
// rows fit in the viewport and use that as the page size, so zooming
// out (more available height) shows more rows instead of empty space.
const TABLE_OVERHEAD_PX = 360
const ROW_HEIGHT_PX = 46
const MIN_ITEMS_PER_PAGE = 10

function computeItemsPerPage() {
  if (typeof window === 'undefined') return 20
  const fits = Math.floor((window.innerHeight - TABLE_OVERHEAD_PX) / ROW_HEIGHT_PX)
  return Math.max(MIN_ITEMS_PER_PAGE, fits)
}

const ISSUE_COLUMNS = [
  { key: 'issue_id', label: 'Issue ID' },
  { key: 'asset_id', label: 'Asset' },
  { key: 'asset_type', label: 'Type' },
  { key: 'cve_id', label: 'CVE / ID' },
  { key: 'severity', label: 'Severity' },
  { key: 'derived_risk', label: 'Derived Risk' },
  { key: 'description', label: 'Description' },
  { key: 'threat_vector', label: 'Threat Vector' },
  { key: 'remediable', label: 'Remediable' },
  { key: 'source', label: 'Source' },
  { key: 'first_detected', label: 'First Detected' },
  { key: 'cve_published', label: 'CVE Published' },
]

export default function Issues() {
  const [searchParams] = useSearchParams()
  const issueIdParam = searchParams.get('issue_id') || ''
  const [searchTerm, setSearchTerm] = useState(issueIdParam)
  const [selectedSeverity, setSelectedSeverity] = useState([])
  const [currentPage, setCurrentPage] = useState(1)
  const { issues } = useIssuesData()
  const [visibleColumns, setVisibleColumns] = useState(ISSUE_COLUMNS.map(c => c.key).filter(k => k !== 'cve_published' && k !== 'description'))
  const [selectedIssue, setSelectedIssue] = useState(null)
  // Items-per-page adapts to viewport height — zoom out or use a tall screen
  // and you'll see more rows automatically instead of empty space.
  const [itemsPerPage, setItemsPerPage] = useState(() => computeItemsPerPage())

  // Sync search term if navigated with a new issue_id param
  useEffect(() => {
    if (issueIdParam) {
      setSearchTerm(issueIdParam)
      setCurrentPage(1)
    }
  }, [issueIdParam])

  useEffect(() => {
    const onResize = () => setItemsPerPage(computeItemsPerPage())
    window.addEventListener('resize', onResize)
    return () => window.removeEventListener('resize', onResize)
  }, [])

  const isVisible = (key) => visibleColumns.includes(key)

  const positionTooltip = useCallback((e) => {
    const cell = e.currentTarget
    const tooltip = cell.querySelector('.threat-vector-tooltip, .derived-risk-tooltip')
    if (!tooltip) return
    const rect = cell.getBoundingClientRect()
    const tooltipHeight = tooltip.offsetHeight
    let top = rect.top + rect.height / 2 - tooltipHeight / 2
    top = Math.max(8, Math.min(top, window.innerHeight - tooltipHeight - 8))
    tooltip.style.top = top + 'px'
    tooltip.style.left = (rect.left - tooltip.offsetWidth - 10) + 'px'
  }, [])

  const filteredIssues = issues.filter(issue => {
    const matchesSeverity =
      selectedSeverity.length === 0 ||
      selectedSeverity.includes(issue.severity)

    const matchesSearch = searchTerm === '' ||
      issue.issue_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      issue.cve_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      issue.description?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      issue.asset_id?.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesSeverity && matchesSearch
  })

  const totalPages = Math.ceil(filteredIssues.length / itemsPerPage)
  const startIndex = (currentPage - 1) * itemsPerPage
  const paginatedIssues = filteredIssues.slice(startIndex, startIndex + itemsPerPage)

  const getSeverityClass = (severity) => {
    if (!severity) return 'low'
    const sev = severity.toUpperCase()
    if (sev === 'CRITICAL') return 'critical'
    if (sev === 'HIGH') return 'high'
    if (sev === 'MEDIUM') return 'medium'
    return 'low'
  }

  return (
    <div className="issues-page-wrapper">
      <Topbar />
      <div className="issues-layout">
        <Sidebar />
        <main className="issues-main">
          <div className="issues-header">
            <h1>Issues</h1>
            <p className="issues-subtitle">Track and manage security vulnerabilities across your assets</p>
          </div>

          <div className="issues-card">
            <div className="issues-filters">
              <div className="issues-chip active">
                {selectedSeverity.length === 0
                  ? 'All'
                  : selectedSeverity.join(', ')
                }
                ({filteredIssues.length})
              </div>

              <div className="issues-toolbar">
                <div className="issues-search">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                  </svg>
                  <input
                    type="text"
                    placeholder="Search by CVE, description, or asset..."
                    value={searchTerm}
                    onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1);
                    }}
                  />
                </div>

                <div className="toolbar-actions">
                  <button className="toolbar-btn" title="Export CSV">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"></path>
                      <polyline points="7 10 12 15 17 10"></polyline>
                      <line x1="12" y1="15" x2="12" y2="3"></line>
                    </svg>
                  </button>
                </div>

                <ColumnToggle
                  columns={ISSUE_COLUMNS}
                  visibleColumns={visibleColumns}
                  onChange={setVisibleColumns}
                />
                <SeverityFilter
                  data={issues}
                  value={selectedSeverity}
                  onChange={(val) => {
                    setSelectedSeverity(val)
                    setCurrentPage(1)
                  }}
                />
              </div>
            </div>

            <div className="issues-table-container">
              <table className="issues-table">
                <thead>
                  <tr>
                    {isVisible('issue_id') && <th>ISSUE ID</th>}
                    {isVisible('asset_id') && <th>ASSET</th>}
                    {isVisible('asset_type') && <th>TYPE</th>}
                    {isVisible('cve_id') && <th>CVE / ID</th>}
                    {isVisible('severity') && <th>SEVERITY</th>}
                    {isVisible('derived_risk') && (
                      <th>
                        <span className="th-tooltip">
                          DERIVED RISK
                          <span className="th-tooltip-text">Derived by Sisy</span>
                        </span>
                      </th>
                    )}
                    {isVisible('description') && <th>DESCRIPTION</th>}
                    {isVisible('threat_vector') && <th>THREAT VECTOR</th>}
                    {isVisible('remediable') && <th>REMEDIABLE</th>}
                    {isVisible('source') && <th>SOURCE</th>}
                    {isVisible('first_detected') && <th>FIRST DETECTED</th>}
                    {isVisible('cve_published') && <th>CVE PUBLISHED</th>}
                  </tr>
                </thead>
                <tbody>
                  {paginatedIssues.length === 0 ? (
                    <tr>
                      <td colSpan="100" className="issues-empty">
                        No issues found matching your criteria
                      </td>
                    </tr>
                  ) : (
                    paginatedIssues.map((issue) => (
                      <tr key={issue.issue_id} onClick={() => setSelectedIssue(issue)} style={{ cursor: 'pointer' }}>
                        {isVisible('issue_id') && (
                          <td>
                            <span className="issues-id-badge">{issue.issue_id}</span>
                          </td>
                        )}
                        {isVisible('asset_id') && (
                          <td>
                            <div className="combined-cell">
                              <span className="validation-id-badge">{issue.asset_id}</span>
                              <span className="combined-secondary">{issue.asset_name}</span>
                            </div>
                          </td>
                        )}
                        {isVisible('asset_type') && (
                          <td>
                            <span className="issues-asset-type">{issue.asset_type}</span>
                          </td>
                        )}
                        {isVisible('cve_id') && (
                          <td>
                            <span className="issues-cve">{issue.cve_id}</span>
                          </td>
                        )}
                        {isVisible('severity') && (
                          <td>
                            <span className={`issues-severity-badge ${getSeverityClass(issue.severity)}`}>
                              {issue.severity}
                            </span>
                          </td>
                        )}
                        {isVisible('derived_risk') && (
                          <td className="td-derived-risk">
                            <div className="derived-risk-cell" onMouseEnter={positionTooltip}>
                              <span className={`issues-score ${getSeverityClass(issue.severity)}`}>
                                {issue.derived_risk}
                              </span>
                              <div className="derived-risk-tooltip">
                                <div className="tooltip-title">Risk Breakdown</div>
                                <div className="tooltip-row">
                                  <span>CVSS Score</span>
                                  <span>{issue.cvss_score != null ? issue.cvss_score : (issue.derived_risk / 10).toFixed(1)}</span>
                                </div>
                                <div className="tooltip-row">
                                  <span>Asset Exposure</span>
                                  <span>{issue.threat_vector === 'Network' ? 'Public' : 'Internal'}</span>
                                </div>
                                <div className="tooltip-row">
                                  <span>Data Sensitivity</span>
                                  <span>{issue.derived_risk > 80 ? 'Contains PII' : 'Standard'}</span>
                                </div>
                              </div>
                            </div>
                          </td>
                        )}
                        {isVisible('description') && (
                          <td className="issues-cell-desc">
                            <span title={issue.description}>{issue.description}</span>
                          </td>
                        )}
                        {isVisible('threat_vector') && (
                          <td className="td-threat-vector">
                            <div className="threat-vector-cell" onMouseEnter={positionTooltip}>
                              <span className="issues-vector">{issue.threat_vector}</span>
                              <div className="threat-vector-tooltip">
                                <div className="tooltip-title">Threat Intelligence</div>

                                <div className="tooltip-section-label">NVD (CVSS v3.1)</div>
                                <div className="tooltip-row">
                                  <span>Attack Vector</span>
                                  <span>{issue.threat_vector || '—'}</span>
                                </div>
                                <div className="tooltip-row">
                                  <span>Attack Complexity</span>
                                  <span>{issue.attack_complexity || '—'}</span>
                                </div>
                                <div className="tooltip-row">
                                  <span>Privileges Required</span>
                                  <span>{issue.privileges_required || '—'}</span>
                                </div>
                                <div className="tooltip-row">
                                  <span>User Interaction</span>
                                  <span>{issue.user_interaction || '—'}</span>
                                </div>
                                <div className="tooltip-row">
                                  <span>CVSS Score</span>
                                  <span className={`tooltip-score ${getSeverityClass(issue.severity)}`}>
                                    {issue.cvss_score != null ? issue.cvss_score : '—'}
                                  </span>
                                </div>

                                {issue.epss_score != null && (
                                  <>
                                    <div className="tooltip-section-label">EPSS (FIRST)</div>
                                    <div className="tooltip-row">
                                      <span>Exploit Probability</span>
                                      <span className="tooltip-epss">
                                        {(issue.epss_score * 100).toFixed(1)}%
                                      </span>
                                    </div>
                                  </>
                                )}

                                {issue.first_detected && (
                                  <>
                                    <div className="tooltip-section-label">Timeline</div>
                                    <div className="tooltip-row">
                                      <span>First Detected</span>
                                      <span>{new Date(issue.first_detected).toLocaleDateString()}</span>
                                    </div>
                                    {issue.cve_published && (
                                      <div className="tooltip-row">
                                        <span>CVE Published</span>
                                        <span>{new Date(issue.cve_published).toLocaleDateString()}</span>
                                      </div>
                                    )}
                                  </>
                                )}

                                {issue.cve_status && (
                                  <div className="tooltip-row">
                                    <span>Status</span>
                                    <span className={`tooltip-status ${issue.cve_status === 'Analyzed' ? 'analyzed' : ''}`}>
                                      {issue.cve_status}
                                    </span>
                                  </div>
                                )}

                                <div className="tooltip-source-tag">
                                  Source: {issue.source}
                                </div>
                              </div>
                            </div>
                          </td>
                        )}
                        {isVisible('remediable') && (
                          <td>
                            <span className={`issues-remediable ${issue.remediable ? 'yes' : 'no'}`}>
                              {issue.remediable ? 'Yes' : 'No'}
                            </span>
                          </td>
                        )}
                        {isVisible('source') && (
                          <td>
                            <span className="issues-source">{issue.source}</span>
                          </td>
                        )}
                        {isVisible('first_detected') && (
                          <td>
                            <span className="issues-date">
                              {issue.first_detected ? new Date(issue.first_detected).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                            </span>
                          </td>
                        )}
                        {isVisible('cve_published') && (
                          <td>
                            <span className="issues-date">
                              {issue.cve_published ? new Date(issue.cve_published).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                            </span>
                          </td>
                        )}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="issues-footer">
              <span className="issues-count">
                Showing {startIndex + 1}-{Math.min(startIndex + itemsPerPage, filteredIssues.length)} of {filteredIssues.length} issues
              </span>

              {totalPages > 1 && (
                <div className="issues-pagination">
                  {/* Previous button */}
                  <button
                    className="pagination-btn"
                    onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                    disabled={currentPage === 1}
                  >
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                  </button>

                  {/* First page */}
                  {currentPage > 3 && (
                    <>
                      <button className="pagination-btn" onClick={() => setCurrentPage(1)}>1</button>
                      {currentPage > 4 && <span className="pagination-dots">...</span>}
                    </>
                  )}

                  {/* Current page range */}
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    const page = Math.max(1, Math.min(totalPages - 4, currentPage - 2)) + i
                    if (page > totalPages) return null
                    return (
                      <button
                        key={page}
                        className={`pagination-btn ${currentPage === page ? 'active' : ''}`}
                        onClick={() => setCurrentPage(page)}
                      >
                        {page}
                      </button>
                    )
                  })}

                  {/* Last page */}
                  {currentPage < totalPages - 2 && (
                    <>
                      {currentPage < totalPages - 3 && <span className="pagination-dots">...</span>}
                      <button className="pagination-btn" onClick={() => setCurrentPage(totalPages)}>{totalPages}</button>
                    </>
                  )}

                  {/* Next button */}
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
      </div>

      {/* Issue Detail Dialog */}
      {selectedIssue && (
        <div className="issue-detail-overlay" onClick={() => setSelectedIssue(null)}>
          <div className="issue-detail-drawer" onClick={(e) => e.stopPropagation()}>
            <div className="issue-drawer-header">
              <div className="issue-drawer-title">
                <span className="issue-drawer-id">{selectedIssue.issue_id}</span>
                <span className={`issue-drawer-severity ${getSeverityClass(selectedIssue.severity)}`}>
                  {selectedIssue.severity}
                </span>
              </div>
              <button className="issue-drawer-close" onClick={() => setSelectedIssue(null)}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <line x1="18" y1="6" x2="6" y2="18"></line>
                  <line x1="6" y1="6" x2="18" y2="18"></line>
                </svg>
              </button>
            </div>

            <div className="issue-drawer-content">
              <div className="issue-drawer-section">
                <div className="issue-drawer-cve">{selectedIssue.cve_id || '—'}</div>
              </div>

              <div className="issue-drawer-section">
                <ul className="issue-drawer-points">
                  {(selectedIssue.description || 'No description available').split('. ').filter(Boolean).map((point, i) => (
                    <li key={i}>{point.trim()}{point.endsWith('.') ? '' : '.'}</li>
                  ))}
                </ul>
              </div>

              <div className="issue-drawer-grid">
                <div className="issue-drawer-item">
                  <span className="issue-drawer-label">Asset</span>
                  <span className="issue-drawer-value">{selectedIssue.asset_name || selectedIssue.asset_id || '—'}</span>
                </div>
                <div className="issue-drawer-item">
                  <span className="issue-drawer-label">Asset Type</span>
                  <span className="issue-drawer-value">{selectedIssue.asset_type || '—'}</span>
                </div>
                <div className="issue-drawer-item">
                  <span className="issue-drawer-label">Derived Risk</span>
                  <span className={`issue-drawer-risk ${getSeverityClass(selectedIssue.severity)}`}>
                    {selectedIssue.derived_risk || '—'}
                  </span>
                </div>
                <div className="issue-drawer-item">
                  <span className="issue-drawer-label">Threat Vector</span>
                  <span className="issue-drawer-value">{selectedIssue.threat_vector || '—'}</span>
                </div>
                <div className="issue-drawer-item">
                  <span className="issue-drawer-label">Remediable</span>
                  <span className={`issue-drawer-remediable ${selectedIssue.remediable === 'Yes' ? 'yes' : 'no'}`}>
                    {selectedIssue.remediable || '—'}
                  </span>
                </div>
                <div className="issue-drawer-item">
                  <span className="issue-drawer-label">Source</span>
                  <span className="issue-drawer-value">{selectedIssue.source || '—'}</span>
                </div>
                <div className="issue-drawer-item">
                  <span className="issue-drawer-label">First Detected</span>
                  <span className="issue-drawer-value">
                    {selectedIssue.first_detected ? new Date(selectedIssue.first_detected).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }) : '—'}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
