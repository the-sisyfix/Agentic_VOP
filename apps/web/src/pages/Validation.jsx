import { useState, useEffect } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import ColumnToggle, { useColumnVisibility } from '../components/ColumnToggle'
import '../styles/Validation.css'
import SeverityFilter from '../components/SeverityFilter'
import ViewToggleEyeDropdown from '../components/ViewToggleEye'
import Tooltip from '../components/Tooltip'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const validationColumns = [
  { key: 'issue_id', label: 'Issue ID' },
  { key: 'issue_name', label: 'Issue' },
  { key: 'asset_id', label: 'Asset ID' },
  { key: 'asset_type', label: 'Asset Type' },
  { key: 'asset_name', label: 'Asset' },
  { key: 'severity', label: 'Severity' },
  { key: 'pathways', label: 'Pathway' },
  { key: 'status', label: 'Status' },
  { key: 'environment', label: 'Environment' },
  { key: 'evidence', label: 'Evidence' },
  { key: 'next_step', label: 'Next Step' },
]

function getStatusClass(status) {
  if (status === 'Validated') return 'validated'
  if (status === 'Failed') return 'failed'
  // Partial reuses the existing "action-needed" pill styling (amber).
  if (status === 'Partial' || status === 'Action Needed') return 'action-needed'
  if (status === 'Closed') return 'closed'
  return 'pending'
}

function getSeverityClassStatic(severity) {
  if (!severity) return 'low'
  const sev = severity.toUpperCase()
  if (sev === 'CRITICAL') return 'critical'
  if (sev === 'HIGH') return 'high'
  if (sev === 'MEDIUM') return 'medium'
  return 'low'
}

function getSeverityColor(severity) {
  const sev = severity?.toUpperCase()
  if (sev === 'CRITICAL') return '#EF4444'
  if (sev === 'HIGH') return '#F97316'
  if (sev === 'MEDIUM') return '#EAB308'
  return '#10B981'
}

function getComplexityColor(complexity) {
  const comp = complexity?.toLowerCase()
  if (comp === 'complex') return '#EF4444'
  if (comp === 'medium') return '#F59E0B'
  return '#10B981'
}

function getStatusExplanation(status, item) {
  if (status === 'Failed') {
    return `Validation failed: ${item.evidence?.description || 'The remediation did not pass verification tests.'}`
  }
  if (status === 'Partial' || status === 'Action Needed') {
    return `Partial — ${item.evidence?.description || 'Some validation checks passed but at least one is incomplete.'}`
  }
  return null
}

function EvidenceModal({ isOpen, onClose, item, evidenceMap = {} }) {
  const [activePath, setActivePath] = useState(0)
  const [selectedStep, setSelectedStep] = useState(0)

  if (!isOpen || !item) return null

  const evidenceData = evidenceMap[item.issue_id]
  const paths = evidenceData?.paths || [{ id: 1, name: 'Direct Fix', coverage: '100%', steps: evidenceData?.steps || [], evidence: evidenceData?.evidence }]
  const currentPath = paths[activePath] || paths[0]
  const pathEvidence = currentPath.evidence || evidenceData?.evidence || ''

  // Enhance steps with validation data
  const steps = (currentPath.steps || []).map((step, index) => {
    if (step.validation) return step
    const status = step.validated ? 'Validated' : (index === 0 ? 'Action Needed' : 'Pending')
    return {
      ...step,
      validation: {
        status,
        scripts: [`${step.action} Verification`, `v${step.version} Security Test`],
        description: step.validated
          ? `Successfully completed: ${step.action}. Target severity reduced to ${step.targetSeverity}.`
          : `Pending validation for: ${step.action}. Estimated time: ${step.time}.`,
        details: pathEvidence
      }
    }
  })

  const handlePathChange = (idx) => {
    setActivePath(idx)
    setSelectedStep(0)
  }

  return (
    <div className="evidence-modal-overlay" onClick={onClose}>
      <div className="evidence-modal enhanced" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="evidence-modal-header">
          <div className="evidence-modal-title-section">
            <h2>Validation Evidence</h2>
            <p>{item.issue_name || item.issue_id}</p>
          </div>
          <div className="evidence-modal-badges">
            <span className={`evidence-status-badge ${getStatusClass(item.status)}`}>
              {item.status}
            </span>
            <span className={`evidence-severity-badge ${getSeverityClassStatic(item.severity)}`}>
              {item.severity}
            </span>
          </div>
          <button className="evidence-modal-close" onClick={onClose}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <line x1="18" y1="6" x2="6" y2="18"></line>
              <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
          </button>
        </div>

        <div className="evidence-modal-content">
          <div className="evidence-fixed-section">
            <div className="evidence-info-bar">
              <div className="evidence-info-item">
                <span className="evidence-info-label">Issue ID</span>
                <span className="evidence-info-value">{item.issue_id}</span>
              </div>
              <div className="evidence-info-item">
                <span className="evidence-info-label">Asset</span>
                <span className="evidence-info-value">{item.asset_name}</span>
              </div>
              <div className="evidence-info-item">
                <span className="evidence-info-label">Environment</span>
                <span className="evidence-info-value">{item.environment}</span>
              </div>
              <div className="evidence-info-item">
                <span className="evidence-info-label">Pathway</span>
                <span className="evidence-info-value">{item.pathways}</span>
              </div>
            </div>

            {/* Remediation Path Tabs */}
            <div className="upgrade-steps-section">
              <div className="evidence-section-header">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 2L2 7l10 5 10-5-10-5z"></path>
                  <path d="M2 17l10 5 10-5"></path>
                  <path d="M2 12l10 5 10-5"></path>
                </svg>
                <h3>Remediation Paths</h3>
                <span className="steps-instruction">Select a path to view steps & evidence</span>
              </div>

              <div className="step-pills-row">
                {paths.map((path, index) => {
                  const label = path.name === 'Direct Fix' ? 'Direct' : path.name === 'Stepped Fix' ? 'Stepped' : path.name
                  return (
                    <button
                      key={path.id}
                      className={`step-pill ${activePath === index ? 'selected' : ''} complexity-${index === 0 ? 'easy' : index === 1 ? 'medium' : 'complex'}`}
                      onClick={() => handlePathChange(index)}
                    >
                      <span className="step-pill-number">{label}</span>
                    </button>
                  )
                })}
              </div>

              <div style={{ textAlign: 'center', marginTop: '6px', fontSize: '10px', fontWeight: 600, color: currentPath.coverage === '100%' ? '#10B981' : '#F59E0B' }}>
                {currentPath.coverage === '100%' ? `Fixes 100% — ${currentPath.description || ''}` : `Mitigates ${currentPath.coverage} — ${currentPath.description || ''}`}
              </div>
            </div>

            {/* Step pills within selected path */}
            {steps.length > 0 && (
              <div style={{ padding: '0 20px', marginTop: '8px' }}>
                <div className="step-pills-row">
                  {steps.map((step, index) => (
                    <button
                      key={index}
                      className={`step-pill ${selectedStep === index ? 'selected' : ''} complexity-${step.complexity?.toLowerCase() === 'complex' ? 'complex' : step.complexity?.toLowerCase() === 'medium' ? 'medium' : 'easy'}`}
                      onClick={() => setSelectedStep(index)}
                      style={{ fontSize: '10px', padding: '6px 10px' }}
                    >
                      <span className="step-pill-number">Step {index + 1}: v{step.version}</span>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Scrollable Section - Step Details */}
          <div className="evidence-scrollable-section">
            {steps.length === 0 ? (
              <div className="no-steps-message">
                No upgrade steps defined for this path
              </div>
            ) : selectedStep !== null && steps[selectedStep] ? (
              <div className="step-details-panel">
                <div className="step-details-header">
                  <div className="step-details-title">
                    <span className="step-details-number">Step {selectedStep + 1}</span>
                    <span className="step-details-version">v{steps[selectedStep].version}</span>
                  </div>
                </div>

                <div className="step-details-action">
                  {steps[selectedStep].action}
                </div>

                <div className="step-details-meta">
                  <div className="step-meta-item">
                    <span className="meta-label">Severity</span>
                    <span className="meta-value-pill" style={{ background: `${getSeverityColor(steps[selectedStep].targetSeverity)}15`, color: getSeverityColor(steps[selectedStep].targetSeverity), borderColor: `${getSeverityColor(steps[selectedStep].targetSeverity)}30` }}>
                      ↓ {steps[selectedStep].targetSeverity}
                    </span>
                  </div>
                  <div className="step-meta-item">
                    <span className="meta-label">Complexity</span>
                    <span className="meta-value-pill" style={{ background: `${getComplexityColor(steps[selectedStep].complexity)}15`, color: getComplexityColor(steps[selectedStep].complexity), borderColor: `${getComplexityColor(steps[selectedStep].complexity)}30` }}>
                      {steps[selectedStep].complexity}
                    </span>
                  </div>
                  <div className="step-meta-item">
                    <span className="meta-label">Status</span>
                    <span className={`meta-value-pill status-pill ${steps[selectedStep].validated ? 'validated' : 'not-validated'}`}>
                      {steps[selectedStep].validated ? '✓ Validated' : '○ Not Validated'}
                    </span>
                  </div>
                  <div className="step-meta-item">
                    <span className="meta-label">Est. Time</span>
                    <span className="meta-value">{steps[selectedStep].time}</span>
                  </div>
                </div>

                {/* Evidence Section */}
                <div className="step-evidence-content">
                  <div className="evidence-subsection">
                    <span className="evidence-subsection-label">Description</span>
                    <p className="evidence-subsection-text">
                      {steps[selectedStep].validation?.description}
                    </p>
                  </div>

                  <div className="evidence-subsection">
                    <span className="evidence-subsection-label">Validation Commands</span>
                    <div className="evidence-code-block compact">
                      <pre>{steps[selectedStep].validation?.details}</pre>
                    </div>
                  </div>
                </div>
              </div>
            ) : null}
          </div>
        </div>

        <div className="evidence-modal-footer">
          <button className="evidence-btn-secondary" onClick={onClose}>Close</button>
          <button className="evidence-btn-primary">Run All Validations</button>
        </div>
      </div>
    </div>
  )
}

export default function Validation() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedSeverity, setSelectedSeverity] = useState([])
  const [currentPage, setCurrentPage] = useState(1)
  const [viewMode, setViewMode] = useState('issue')
  const [evidenceModalOpen, setEvidenceModalOpen] = useState(false)
  const [selectedEvidence, setSelectedEvidence] = useState(null)
  const [statusOverrides, setStatusOverrides] = useState({})
  // Hydrate from localStorage so the Validation page paints instantly on
  // revisits instead of flashing "No validations found" during the fetch.
  const _cachedValidations = (() => {
    try {
      const raw = localStorage.getItem('sisyfix:validations:v1')
      if (!raw) return null
      const c = JSON.parse(raw)
      if (!c?.ts || Date.now() - c.ts > 24 * 60 * 60 * 1000) return null
      return c.rows || null
    } catch { return null }
  })()
  const [validationsData, setValidationsData] = useState(_cachedValidations || [])
  const [remediationEvidenceData, setRemediationEvidenceData] = useState({})
  const [loading, setLoading] = useState(!_cachedValidations)

  const itemsPerPage = 10

  // Fetch remediation packages from demo API and map to validation format
  useEffect(() => {
    async function loadValidations() {
      try {
        // Use demo pipeline — includes pathways inline
        const res = await fetch(`${API_URL}/admin/remediation-packages/demo`)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        const packages = data.packages || []

        if (packages.length === 0) {
          setLoading(false)
          return
        }

        const mapped = packages.map(pkg => {
          const pwIdx = pkg.recommended_pathway_index ?? 0
          const pw = pkg.pathways?.[pwIdx] || pkg.pathways?.[0]
          const vm = pw?.validation_metadata

          // Determine validation status from package data.
          // Mapping mirrors the Remediation page's VALIDATION_LABEL so both
          // surfaces show the same word for the same underlying state.
          //   validated | proven  -> "Validated"
          //   partial  | unverified -> "Partial"
          //   unvalidated        -> "Failed"
          //   null (no metadata) -> "Pending"
          let status = 'Pending'
          if (vm?.status === 'validated' || vm?.status === 'proven') status = 'Validated'
          else if (vm?.status === 'partial' || vm?.status === 'unverified') status = 'Partial'
          else if (vm?.status === 'unvalidated') status = 'Failed'
          else if (pkg.status === 'ready_for_execution') status = 'Validated'
          else if (pkg.status === 'rejected') status = 'Failed'

          // Determine severity from family
          let severity = 'MEDIUM'
          if (pkg.family === 'injection' || pkg.family === 'public_exposure') severity = 'CRITICAL'
          else if (pkg.family === 'os_vulnerability' || pkg.family === 'network_exposure') severity = 'HIGH'

          // Build evidence data for the modal
          const steps = (pw?.remediation_steps || []).map((s, i) => ({
            version: `${i + 1}.0.0`,
            action: s.step,
            targetSeverity: i === 0 ? severity : 'LOW',
            complexity: i === 0 ? 'Medium' : 'Easy',
            time: '~2 hours',
            validated: vm?.status === 'validated',
          }))

          const evidenceText = pw?.validation_tests?.map(t =>
            `# ${t.name}\n${t.command}\n# Expected: ${t.expected}`
          ).join('\n\n') || `# Package #${pkg.id}\n# Confidence: ${pw?.confidence_score || '—'}/100`

          return {
            issue_id: pkg.issue_id ? `ISS-${String(pkg.issue_id).padStart(5, '0')}` : `PKG-${String(pkg.id).padStart(4, '0')}`,
            issue_name: pkg.finding || 'Untitled',
            asset_id: `PKG-${String(pkg.id).padStart(4, '0')}`,
            asset_name: pkg.family ? pkg.family.replace(/_/g, ' ') : '',
            asset_type: pkg.family === 'os_vulnerability' ? 'Server' : pkg.family === 'injection' ? 'Application' : pkg.family === 'network_exposure' ? 'Network' : pkg.family === 'public_exposure' ? 'Cloud' : 'Container',
            severity,
            pathways: pw?.objective?.slice(0, 50) || 'Direct Fix',
            status,
            environment: pkg.family === 'os_vulnerability' ? 'Production' : 'Development',
            evidence: { description: pw?.execution_strategy || '' },
            _pkg: pkg,
            _steps: steps,
            _evidenceText: evidenceText,
          }
        })

        setValidationsData(mapped)
        try {
          localStorage.setItem('sisyfix:validations:v1', JSON.stringify({ ts: Date.now(), rows: mapped }))
        } catch { /* best-effort */ }

        // Build evidence map for the modal
        const evidenceMap = {}
        mapped.forEach(item => {
          evidenceMap[item.issue_id] = {
            steps: item._steps,
            evidence: item._evidenceText,
            paths: [
              { id: 1, name: 'Direct Fix', coverage: '100%', description: 'Full remediation', steps: item._steps, evidence: item._evidenceText },
              { id: 2, name: 'Stepped Fix', coverage: '100%', description: 'Incremental', steps: item._steps, evidence: item._evidenceText },
              { id: 3, name: 'Workaround', coverage: '60%', description: 'Partial mitigation', steps: item._steps.slice(0, 1), evidence: item._evidenceText },
            ],
          }
        })
        setRemediationEvidenceData(evidenceMap)
      } catch (e) {
        console.error('Failed to load validations:', e)
      } finally {
        setLoading(false)
      }
    }
    loadValidations()
  }, [])

  const assetTypeMap = {}

  const validations = validationsData.map(v => ({
    ...v,
    asset_type: assetTypeMap[v.asset_id] || 'Unknown',
    status: statusOverrides[v.issue_id] || v.status
  }))

  const { visibleColumns, setVisibleColumns, isVisible } = useColumnVisibility(validations, [], [])

  const filteredValidations = validations.filter(item => {
    const matchesFilter = selectedSeverity.length === 0 || selectedSeverity.includes(item.severity)
    const matchesSearch = searchTerm === '' ||
      item.issue_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.asset_id?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.issue_name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
      item.asset_name?.toLowerCase().includes(searchTerm.toLowerCase())
    return matchesFilter && matchesSearch
  })

  const startIndex = (currentPage - 1) * itemsPerPage
  const tableData = filteredValidations
  const totalPages = Math.ceil(tableData.length / itemsPerPage)
  const paginatedData = tableData.slice(startIndex, startIndex + itemsPerPage)

  const getSeverityClass = (severity) => {
    if (!severity) return 'low'
    const sev = severity.toUpperCase()
    if (sev === 'CRITICAL') return 'CRITICAL'
    if (sev === 'HIGH') return 'HIGH'
    if (sev === 'MEDIUM') return 'MEDIUM'
    return 'low'
  }

  const getValidationClass = (status) => {
    if (status === 'Validated') return 'validated'
    if (status === 'Failed') return 'failed'
    if (status === 'Partial' || status === 'Action Needed') return 'action-needed'
    if (status === 'Closed') return 'closed'
    return 'pending'
  }

  const getEnvironmentClass = (env) => {
    if (env === 'Production') return 'production'
    if (env === 'Deployed') return 'deployed'
    if (env === 'Staging') return 'staging'
    return 'development'
  }

  const handleEvidenceClick = (item) => {
    setSelectedEvidence(item)
    setEvidenceModalOpen(true)
  }

  const handleMarkAsClosed = (issueId) => {
    setStatusOverrides(prev => ({ ...prev, [issueId]: 'Closed' }))
  }

  const handleReOpen = (issueId) => {
    setStatusOverrides(prev => ({ ...prev, [issueId]: 'Action Needed' }))
  }

  const handleRetry = (issueId) => { // eslint-disable-line no-unused-vars
    // Wire to validation retry endpoint when ready
  }

  const renderStatusWithTooltip = (item) => {
    const status = item.status
    const explanation = getStatusExplanation(status, item)

    if (explanation) {
      return (
        <Tooltip content={explanation}>
          <span className={`validation-status has-tooltip ${getValidationClass(status)}`}>
            {status}
            <svg className="status-info-icon" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="12" cy="12" r="10"></circle>
              <line x1="12" y1="16" x2="12" y2="12"></line>
              <line x1="12" y1="8" x2="12.01" y2="8"></line>
            </svg>
          </span>
        </Tooltip>
      )
    }

    return (
      <span className={`validation-status ${getValidationClass(status)}`}>{status}</span>
    )
  }

  const renderNextStepButtons = (item) => {
    const status = item.status

    if (status === 'Validated') {
      return (
        <button className="next-step-btn mark-closed" onClick={() => handleMarkAsClosed(item.issue_id)}>
          Mark as Closed
        </button>
      )
    }

    if (status === 'Action Needed') {
      return (
        <div className="next-step-buttons">
          <button className="next-step-btn retry" onClick={() => handleRetry(item.issue_id)}>
            Retry
          </button>
          <button className="next-step-btn mark-closed" onClick={() => handleMarkAsClosed(item.issue_id)}>
            Mark as Closed
          </button>
        </div>
      )
    }

    if (status === 'Failed') {
      return (
        <div className="next-step-buttons">
          <button className="next-step-btn retry" onClick={() => handleRetry(item.issue_id)}>
            Retry
          </button>
          <button className="next-step-btn reopen" onClick={() => handleReOpen(item.issue_id)}>
            Re-Open
          </button>
          <button className="next-step-btn mark-closed" onClick={() => handleMarkAsClosed(item.issue_id)}>
            Mark as Closed
          </button>
        </div>
      )
    }

    if (status === 'Closed') {
      return (
        <button className="next-step-btn reopen" onClick={() => handleReOpen(item.issue_id)}>
          Re-Open
        </button>
      )
    }

    return (
      <button className="next-step-btn mark-closed" onClick={() => handleMarkAsClosed(item.issue_id)}>
        Mark as Closed
      </button>
    )
  }

  // Get step count for an issue (priority: Direct Fix > Stepped Fix > Workaround)
  const getStepCount = (issueId) => {
    const evidence = remediationEvidenceData[issueId]
    if (!evidence) return 0
    const paths = evidence.paths
    if (paths && paths.length > 0) {
      // Priority order: Direct Fix (id 1) > Stepped Fix (id 2) > Workaround (id 3)
      const direct = paths.find(p => p.id === 1)
      if (direct && direct.steps?.length) return direct.steps.length
      const stepped = paths.find(p => p.id === 2)
      if (stepped && stepped.steps?.length) return stepped.steps.length
      const workaround = paths.find(p => p.id === 3)
      if (workaround && workaround.steps?.length) return workaround.steps.length
    }
    return evidence?.steps?.length || 0
  }

  return (
    <div className="validation-page-wrapper">
      <Topbar />
      <div className="validation-layout">
        <Sidebar />
        <main className="validation-main">
          <div className="validation-header">
            <h1>Validation</h1>
            <p className="validation-subtitle">Verify and validate remediation deployments across your infrastructure</p>
          </div>

          <div className="validation-card">
            <div className="validation-filters">
              <div className="validation-chip active">
                {selectedSeverity.length === 0 ? 'All' : selectedSeverity.join(', ')}
                ({filteredValidations.length})
              </div>

              <div className="validation-toolbar">
                <div className="validation-search">
                  <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <circle cx="11" cy="11" r="8"></circle>
                    <path d="m21 21-4.35-4.35"></path>
                  </svg>
                  <input
                    type="text"
                    placeholder="Search by issue ID, asset, or name..."
                    value={searchTerm}
                    onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
                  />
                </div>

                <ColumnToggle
                  data={validations}
                  columns={validationColumns}
                  visibleColumns={visibleColumns}
                  onChange={setVisibleColumns}
                />
                <SeverityFilter
                  data={validations}
                  value={selectedSeverity}
                  onChange={(val) => { setSelectedSeverity(val); setCurrentPage(1) }}
                />
                <ViewToggleEyeDropdown
                  viewMode={viewMode}
                  onChange={(mode) => { setViewMode(mode); setCurrentPage(1) }}
                />
              </div>
            </div>

            <div className="validation-table-container">
              <table className="validation-table" key={viewMode}>
                <thead>
                  <tr>
                    {viewMode === 'issue' ? (
                      <>
                        <th>ISSUE ID</th>
                        {isVisible('asset_name') && <th>ASSET</th>}
                        {isVisible('environment') && <th>ENVIRONMENT</th>}
                      </>
                    ) : (
                      <>
                        <th>ASSET ID</th>
                        {isVisible('asset_type') && <th>ASSET TYPE</th>}
                      </>
                    )}
                    {isVisible('severity') && <th>SEVERITY</th>}
                    {isVisible('pathways') && <th>PATHWAY</th>}
                    {isVisible('status') && <th>STATUS</th>}
                    {isVisible('evidence') && <th>EVIDENCE</th>}
                    {isVisible('next_step') && <th>NEXT STEP</th>}
                  </tr>
                </thead>
                <tbody>
                  {paginatedData.length === 0 ? (
                    loading && validationsData.length === 0 ? (
                      Array.from({ length: 8 }).map((_, i) => (
                        <tr key={`skeleton-${i}`} className="validation-skeleton-row">
                          <td colSpan="100">
                            <span className="skeleton-block" style={{ height: 14, width: '95%' }} />
                          </td>
                        </tr>
                      ))
                    ) : (
                      <tr>
                        <td colSpan="100" className="validation-empty">No validations found</td>
                      </tr>
                    )
                  ) : (
                    paginatedData.map(item => (
                      <tr key={`${viewMode}-${item.issue_id}`}>
                        {viewMode === 'issue' ? (
                          <>
                            <td>
                              <span className="validation-id-badge">
                                {item.issue_id}
                              </span>
                            </td>
                            {isVisible('asset_name') && <td className="validation-cell-asset">{item.asset_name}</td>}
                            {isVisible('environment') && (
                              <td><span className={`validation-environment ${getEnvironmentClass(item.environment)}`}>{item.environment}</span></td>
                            )}
                          </>
                        ) : (
                          <>
                            <td>
                              <div className="combined-cell">
                                <span className="validation-id-badge">
                                  {item.asset_id}
                                </span>
                                <span className="combined-secondary">
                                  {item.asset_name}
                                </span>
                              </div>
                            </td>

                            {isVisible('asset_type') && (
                              <td>
                                <span className="validation-asset-type">
                                  {item.asset_type}
                                </span>
                              </td>
                            )}
                          </>
                        )}
                        {isVisible('severity') && (
                          <td><span className={`validation-priority ${getSeverityClass(item.severity)}`}>{item.severity}</span></td>
                        )}
                        {isVisible('pathways') && <td className="validation-cell-pathway">{item.pathways}</td>}
                        {isVisible('status') && <td>{renderStatusWithTooltip(item)}</td>}
                        {isVisible('evidence') && (
                          <td>
                            <button className="evidence-view-btn" onClick={() => handleEvidenceClick(item)}>
                              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                                <polyline points="14 2 14 8 20 8"></polyline>
                              </svg>
                              <span className="evidence-preview">
                                {getStepCount(item.issue_id)} Steps
                              </span>
                            </button>
                          </td>
                        )}
                        {isVisible('next_step') && <td className="validation-cell-next-step">{renderNextStepButtons(item)}</td>}
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            <div className="validation-footer">
              <span className="validation-count">
                Showing {startIndex + 1}-{Math.min(startIndex + itemsPerPage, tableData.length)} of {tableData.length} validations
              </span>
              {totalPages > 1 && (
                <div className="validation-pagination">
                  <button className="pagination-btn" onClick={() => setCurrentPage(p => Math.max(1, p - 1))} disabled={currentPage === 1}>
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="15 18 9 12 15 6"></polyline>
                    </svg>
                  </button>
                  {Array.from({ length: totalPages }, (_, i) => i + 1).map(page => (
                    <button key={page} className={`pagination-btn ${currentPage === page ? 'active' : ''}`} onClick={() => setCurrentPage(page)}>
                      {page}
                    </button>
                  ))}
                  <button className="pagination-btn" onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))} disabled={currentPage === totalPages}>
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

      <EvidenceModal isOpen={evidenceModalOpen} onClose={() => { setEvidenceModalOpen(false); }} item={selectedEvidence} evidenceMap={remediationEvidenceData} />
    </div>
  )
}