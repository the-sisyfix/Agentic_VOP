import { useCallback, useEffect, useMemo, useState } from 'react'
import Sidebar from '../components/Sidebar'
import Topbar from '../components/Topbar'
import '../styles/Remediation.css'
import '../styles/RemediationPackages.css'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

// Pinned demo issue IDs — the 5 Phase-1 vulnerabilities.
const DEMO_ISSUE_IDS = [8585, 8586, 7481, 6394, 7832]

// Header "Remediate" button — hidden by default. Flip to true if you want
// to expose live LLM generation in the UI. Same behaviour as the CLI:
//   uv run python scripts/run_planner.py --persist
// Kept the handleGenerate function + API endpoint intact so re-enabling
// is a one-line change (no backend work).
const SHOW_REMEDIATE_BUTTON = false

const FAMILY_LABEL = {
  public_exposure: 'Public Exposure',
  network_exposure: 'Network Exposure',
  injection: 'Injection',
  vulnerable_dependency: 'Vulnerable Dependency',
  os_vulnerability: 'OS Vulnerability',
}

const STATUS_LABEL = {
  draft: 'Draft',
  awaiting_approval: 'Awaiting Approval',
  approved: 'Approved',
  rejected: 'Rejected',
  ready_for_execution: 'Ready for Execution',
  // Terminal fix-outcome states set by the HITL approve flow after SA-4
  // completes (see main.py approve endpoint background task).
  fixed: 'Fixed',
  rolled_back: 'Rolled Back',
  fix_failed: 'Fix Failed',
  // HITL v2 — post-fix review states. Set by master's status sync when
  // the package was created with review_required=True (see design doc:
  // Post-Fix Review Modes, Approach A · Sandbox).
  awaiting_review: 'Awaiting Review',
  review_rejected: 'Review Rejected',
}

const VALIDATION_TONE = {
  validated: 'good',
  partial: 'warn',
  unvalidated: 'bad',
}

const APPROVAL_LABEL = {
  auto: 'Auto',
  single_approver: 'Single Approver',
  multi_stage: 'Multi-stage',
}

function confidenceTone(score) {
  if (score >= 90) return 'good'
  if (score >= 75) return 'warn'
  return 'bad'
}

function formatDate(iso) {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString()
  } catch {
    return iso
  }
}

function recommendedPathway(pkg) {
  if (!pkg?.pathways || pkg.pathways.length === 0) return null
  const idx = pkg.recommended_pathway_index ?? 0
  return pkg.pathways[idx] || pkg.pathways[0]
}

export default function Remediation() {
  const [packages, setPackages] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [statusFilter, setStatusFilter] = useState('all')
  const [selectedId, setSelectedId] = useState(null)
  const [detail, setDetail] = useState(null)
  // Pagination
  const PAGE_SIZE = 50
  const [currentPage, setCurrentPage] = useState(1)
  const [totalPackages, setTotalPackages] = useState(0)
  const [detailLoading, setDetailLoading] = useState(false)
  const [generating, setGenerating] = useState(false)
  const [toast, setToast] = useState(null)
  // Contextual switch: 'real' or 'demo'. Set by Integrations page buttons,
  // overridable via the pill at the top of the page.
  const [pipelineMode, setPipelineMode] = useState(
    () => localStorage.getItem('pipelineMode') || 'real'
  )

  // Listen for pipelineMode changes from other components / other tabs.
  useEffect(() => {
    const handler = () => {
      setPipelineMode(localStorage.getItem('pipelineMode') || 'real')
    }
    window.addEventListener('pipelineModeChanged', handler)
    window.addEventListener('storage', handler)
    return () => {
      window.removeEventListener('pipelineModeChanged', handler)
      window.removeEventListener('storage', handler)
    }
  }, [])

  const isDemo = pipelineMode === 'demo'
  const apiBase = isDemo
    ? `${API_URL}/admin/remediation-packages/demo`
    : `${API_URL}/admin/remediation-packages`

  const setModeManual = (mode) => {
    localStorage.setItem('pipelineMode', mode)
    window.dispatchEvent(new Event('pipelineModeChanged'))
  }

  const showToast = useCallback((kind, msg) => {
    setToast({ kind, msg })
    setTimeout(() => setToast(null), 3500)
  }, [])

  // silent=true skips the loading flash for background polls
  const refreshList = useCallback(async ({ silent = false } = {}) => {
    if (!silent) setLoading(true)
    setError(null)
    try {
      const offset = (currentPage - 1) * PAGE_SIZE
      const qs = new URLSearchParams({ limit: String(PAGE_SIZE), offset: String(offset) })
      if (statusFilter !== 'all') qs.set('status', statusFilter)
      const res = await fetch(`${apiBase}?${qs}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      const pkgs = data.packages || []
      setPackages(pkgs)
      // Only show the top 50 — don't surface the full DB total (e.g. "of 3184")
      // in the footer. Keeps the UI focused on the most-recent packages.
      setTotalPackages(pkgs.length)
    } catch (e) {
      setError(e.message || 'Failed to load packages')
      if (!silent) setPackages([])
    } finally {
      if (!silent) setLoading(false)
    }
  }, [statusFilter, apiBase, currentPage])

  useEffect(() => { refreshList() }, [refreshList])

  // When the status filter changes, go back to page 1 so we don't request
  // an offset that is now out of range (e.g. filtering down to 10 rows
  // while sitting on page 3).
  useEffect(() => { setCurrentPage(1) }, [statusFilter, apiBase])

  const totalPages = Math.max(1, Math.ceil(totalPackages / PAGE_SIZE))

  // Clear selection when switching modes so demo/real packages don't bleed.
  useEffect(() => {
    setSelectedId(null)
    setDetail(null)
  }, [pipelineMode])

  // Poll silently while in demo mode so the list grows as the pipeline
  // generates packages — no loading-flash on each poll. Stop polling once
  // we've reached 5 packages (a full run's worth) to avoid infinite fetching.
  useEffect(() => {
    if (!isDemo) return
    if (packages.length >= 5) return
    const interval = setInterval(() => { refreshList({ silent: true }) }, 3000)
    return () => clearInterval(interval)
  }, [isDemo, refreshList, packages.length])

  // When a row is selected, load full detail (includes the pathways jsonb).
  useEffect(() => {
    if (selectedId == null) { setDetail(null); return }
    let cancelled = false
    setDetailLoading(true)
    fetch(`${apiBase}/${selectedId}`)
      .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
      .then(d => { if (!cancelled) setDetail(d) })
      .catch(e => { if (!cancelled) { setDetail(null); showToast('error', e.message) } })
      .finally(() => { if (!cancelled) setDetailLoading(false) })
    return () => { cancelled = true }
  }, [selectedId, showToast, apiBase])

  const handleGenerate = useCallback(async () => {
    if (generating) return
    setGenerating(true)
    try {
      const res = await fetch(`${API_URL}/admin/remediation-packages/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ issue_ids: DEMO_ISSUE_IDS }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      const ok = data.packages?.filter(p => p.status === 'created').length || 0
      const total = data.packages?.length || 0
      showToast(ok === total ? 'success' : 'warn',
                `Generated ${ok}/${total} packages`)
      await refreshList()
    } catch (e) {
      showToast('error', `Generate failed: ${e.message}`)
    } finally {
      setGenerating(false)
    }
  }, [generating, refreshList, showToast])

  const handleApprove = useCallback(async (id) => {
    try {
      const res = await fetch(`${apiBase}/${id}/approve`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ approved_by: 'demo-user@acmecorp.com' }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      showToast('success', `Package ${id} approved → ready for execution`)
      await refreshList()
      if (selectedId === id) {
        const refreshed = await fetch(`${apiBase}/${id}`).then(r => r.json())
        setDetail(refreshed)
      }
    } catch (e) {
      showToast('error', `Approve failed: ${e.message}`)
    }
  }, [refreshList, selectedId, showToast, apiBase])

  // HITL v2 — approve the DIFF SA-4 produced. Keeps changes live,
  // finalizes package as `fixed`, cleans up the .bak on env2.
  const handleReviewApprove = useCallback(async (id) => {
    // Route to the git-native or sandbox endpoint based on whether the
    // package has a PR attached. Only one flow ever applies per package.
    const isGitNative = Boolean(detail?.git_pr_url)
    const endpoint = isGitNative ? 'review-git-approve' : 'review-approve'
    const confirmMsg = isGitNative
      ? `Merge PR #${detail?.git_pr_number} on GitHub?\n\nThis will merge the pull request into the base branch. Package will be marked as Fixed.`
      : 'Approve these changes?\n\nThis will keep the file edits SA-4 made and mark the package as Fixed. The backup file will be deleted from env2.'
    if (!window.confirm(confirmMsg)) return
    try {
      const res = await fetch(`${apiBase}/${id}/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewed_by: 'demo-user@acmecorp.com' }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`)
      showToast('success', `Package ${id} — changes approved (Fixed)${isGitNative ? ' · PR merged' : ''}`)
      await refreshList()
      if (selectedId === id) {
        const refreshed = await fetch(`${apiBase}/${id}`).then(r => r.json())
        setDetail(refreshed)
      }
    } catch (e) {
      showToast('error', `Review approve failed: ${e.message}`)
    }
  }, [refreshList, selectedId, showToast, apiBase, detail])

  // HITL v2 — reject the change. Sandbox: SSM restores the .bak on env2.
  // Git-native: closes the PR on GitHub. Package flips to review_rejected.
  const handleReviewReject = useCallback(async (id) => {
    const isGitNative = Boolean(detail?.git_pr_url)
    const endpoint = isGitNative ? 'review-git-reject' : 'review-reject'
    const confirmMsg = isGitNative
      ? `Close PR #${detail?.git_pr_number} on GitHub without merging?\n\nThe branch stays but no changes land on the base branch. Package will be marked as Review Rejected.`
      : 'Reject these changes?\n\nThis will restore the original file on env2 from the backup, and mark the package as Review Rejected. The fix will be undone.'
    if (!window.confirm(confirmMsg)) return
    try {
      const res = await fetch(`${apiBase}/${id}/${endpoint}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reviewed_by: 'demo-user@acmecorp.com' }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`)
      const data = await res.json()
      const suffix = isGitNative ? ' · PR closed' : ' · file restored'
      showToast('success', `Package ${id} — changes rejected (${data.status})${suffix}`)
      await refreshList()
      if (selectedId === id) {
        const refreshed = await fetch(`${apiBase}/${id}`).then(r => r.json())
        setDetail(refreshed)
      }
    } catch (e) {
      showToast('error', `Review reject failed: ${e.message}`)
    }
  }, [refreshList, selectedId, showToast, apiBase, detail])

  const handleReject = useCallback(async (id) => {
    const reason = window.prompt('Reject reason (will be saved on the package):')
    if (!reason || reason.trim().length < 3) {
      showToast('warn', 'Reject canceled — reason must be ≥3 chars')
      return
    }
    try {
      const res = await fetch(`${apiBase}/${id}/reject`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: reason.trim(), rejected_by: 'demo-user@acmecorp.com' }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      showToast('success', `Package ${id} rejected`)
      await refreshList()
      if (selectedId === id) {
        const refreshed = await fetch(`${apiBase}/${id}`).then(r => r.json())
        setDetail(refreshed)
      }
    } catch (e) {
      showToast('error', `Reject failed: ${e.message}`)
    }
  }, [refreshList, selectedId, showToast, apiBase])

  const statusCounts = useMemo(() => {
    const out = { all: packages.length, awaiting_approval: 0, ready_for_execution: 0, rejected: 0 }
    for (const p of packages) {
      out[p.status] = (out[p.status] || 0) + 1
    }
    return out
  }, [packages])

  // For the stats strip we want totals across ALL statuses, not just the
  // current filter. Quick second fetch when filter isn't 'all'.
  const [globalStats, setGlobalStats] = useState({ total: 0, awaiting: 0, ready: 0, rejected: 0 })
  useEffect(() => {
    // Fetch stats from whichever pipeline is active (real or demo)
    fetch(apiBase)
      .then(r => r.ok ? r.json() : { packages: [] })
      .then(d => {
        const list = d.packages || []
        setGlobalStats({
          total: list.length,
          awaiting: list.filter(p => p.status === 'awaiting_approval').length,
          ready: list.filter(p => p.status === 'ready_for_execution').length,
          rejected: list.filter(p => p.status === 'rejected').length,
        })
      })
      .catch(() => { /* ignore */ })
  }, [packages, apiBase]) // refresh stats whenever the visible list or pipeline mode changes

  return (
    <div className="remediation-page-wrapper">
      <Topbar />
      <div className="remediation-layout">
        <Sidebar />
        <main className="remediation-main">
          <div className="remediation-header rmp-header-flex">
            <div className="rmp-header-text">
              <h1>Remediation</h1>
              <p className="remediation-subtitle">
                Generated remediation packages — validated against authoritative sources, scored for confidence, gated by human approval.
                {isDemo && ' — DEMO PIPELINE (5 pre-seeded issues)'}
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8, marginRight: 12 }}>
              <button
                type="button"
                onClick={() => setModeManual('real')}
                style={{
                  padding: '6px 14px',
                  borderRadius: 999,
                  border: '1px solid ' + (!isDemo ? '#22c55e' : '#334155'),
                  background: !isDemo ? 'rgba(34,197,94,0.15)' : 'transparent',
                  color: !isDemo ? '#22c55e' : '#94a3b8',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Real Pipeline
              </button>
              <button
                type="button"
                onClick={() => setModeManual('demo')}
                style={{
                  padding: '6px 14px',
                  borderRadius: 999,
                  border: '1px solid ' + (isDemo ? '#3b82f6' : '#334155'),
                  background: isDemo ? 'rgba(59,130,246,0.15)' : 'transparent',
                  color: isDemo ? '#3b82f6' : '#94a3b8',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Demo Pipeline
              </button>
            </div>
            {SHOW_REMEDIATE_BUTTON && (
              <button
                className="rmp-header-btn"
                onClick={handleGenerate}
                disabled={generating}
                type="button"
                title="Generate fresh remediation packages for the 5 demo issues"
              >
                {generating ? (
                  <>
                    <span className="rmp-header-btn-dot pulsing">●</span>
                    <span>Remediating…</span>
                  </>
                ) : (
                  <>
                    <span className="rmp-header-btn-dot">⚙</span>
                    <span>Remediate</span>
                  </>
                )}
              </button>
            )}
          </div>

          {/* Stats strip — 4 columns */}
          <div className="rmp-stats">
            <div className="rmp-stat-card">
              <div className="rmp-stat-num">{globalStats.total}</div>
              <div className="rmp-stat-label">Total Packages</div>
            </div>
            <div className="rmp-stat-card warn">
              <div className="rmp-stat-num">{globalStats.awaiting}</div>
              <div className="rmp-stat-label">Awaiting Approval</div>
            </div>
            <div className="rmp-stat-card good">
              <div className="rmp-stat-num">{globalStats.ready}</div>
              <div className="rmp-stat-label">Ready for Execution</div>
            </div>
            <div className="rmp-stat-card bad">
              <div className="rmp-stat-num">{globalStats.rejected}</div>
              <div className="rmp-stat-label">Rejected</div>
            </div>
          </div>

          {/* Toolbar — just filter pills now, action moved into stats strip */}
          <div className="rmp-toolbar">
            <div className="rmp-filter-group">
              {['all', 'awaiting_approval', 'awaiting_review', 'ready_for_execution', 'fixed', 'rolled_back', 'fix_failed', 'review_rejected', 'rejected'].map(s => (
                <button
                  key={s}
                  className={`rmp-filter-pill ${statusFilter === s ? 'active' : ''}`}
                  onClick={() => setStatusFilter(s)}
                >
                  {s === 'all' ? 'All' : STATUS_LABEL[s]}
                  <span className="rmp-pill-count">{statusCounts[s] ?? 0}</span>
                </button>
              ))}
            </div>
          </div>

          {/* List */}
          <div className="rmp-list-card">
            <div className="rmp-list-scroll">
            {loading ? (
              <div className="rmp-empty">Loading packages…</div>
            ) : error ? (
              <div className="rmp-empty bad">Failed to load: {error}</div>
            ) : packages.length === 0 ? (
              <div className="rmp-empty">
                <div className="rmp-empty-title">No remediation packages yet</div>
                <div className="rmp-empty-sub">
                  Click <strong>Generate Demo Packages</strong> above to create one package per
                  demo finding (Sub-Agent 3 + Confidence Engine, ~90s).
                </div>
              </div>
            ) : (
              <table className="rmp-table">
                <thead>
                  <tr>
                    <th>ID</th>
                    <th>Finding</th>
                    <th>Family</th>
                    <th>Confidence</th>
                    <th>Validation</th>
                    <th>Approval</th>
                    <th>Status</th>
                    <th>Created</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {packages.map(p => {
                    // Cells receive the row and the current apiBase — in demo
                    // mode the row already carries `pathways` inline, so no
                    // N+1 fetch. In real mode they fall back to fetching from
                    // apiBase/{id} (the summary-only list doesn't include pathways).
                    return (
                      <tr key={p.id} className={selectedId === p.id ? 'selected' : ''}
                          onClick={() => setSelectedId(p.id)}>
                        <td>#{p.id}</td>
                        <td className="rmp-finding-cell">{p.finding || '—'}</td>
                        <td><span className="rmp-family-chip">{FAMILY_LABEL[p.family] || p.family}</span></td>
                        <td>
                          <ConfidenceCell pkg={p} apiBase={apiBase} />
                        </td>
                        <td>
                          <ValidationCell pkg={p} apiBase={apiBase} />
                        </td>
                        <td>{APPROVAL_LABEL[p.approval_required] || p.approval_required}</td>
                        <td><StatusPill status={p.status} /></td>
                        <td className="rmp-date-cell">{formatDate(p.created_at)}</td>
                        <td>
                          <button className="rmp-view-btn" onClick={(e) => { e.stopPropagation(); setSelectedId(p.id) }}>
                            View →
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            )}
            </div>

            {/* Pagination — matches the Issues page footer so the
                numbered buttons + chevrons + first/last/dots all look
                the same across the app. Pinned at the bottom of the list
                card so it stays visible while the table body scrolls. */}
            {!loading && !error && (
              <div className="issues-footer">
                <span className="issues-count">
                  Showing {(currentPage - 1) * PAGE_SIZE + 1}-{Math.min(currentPage * PAGE_SIZE, totalPackages)} of {totalPackages} packages
                </span>
                {totalPages > 1 && (
                  <div className="issues-pagination">
                    <button
                      className="pagination-btn"
                      onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                    >
                      <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <polyline points="15 18 9 12 15 6"></polyline>
                      </svg>
                    </button>

                    {currentPage > 3 && (
                      <>
                        <button className="pagination-btn" onClick={() => setCurrentPage(1)}>1</button>
                        {currentPage > 4 && <span className="pagination-dots">...</span>}
                      </>
                    )}

                    {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                      const page = Math.max(1, Math.min(totalPages - 4, currentPage - 2)) + i
                      if (page > totalPages || page < 1) return null
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

                    {currentPage < totalPages - 2 && (
                      <>
                        {currentPage < totalPages - 3 && <span className="pagination-dots">...</span>}
                        <button className="pagination-btn" onClick={() => setCurrentPage(totalPages)}>{totalPages}</button>
                      </>
                    )}

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
            )}
          </div>
        </main>

        {/* Detail drawer */}
        {selectedId != null && (
          <DetailDrawer
            pkg={detail}
            loading={detailLoading}
            onClose={() => { setSelectedId(null); setDetail(null) }}
            onApprove={() => handleApprove(selectedId)}
            onReject={() => handleReject(selectedId)}
            onReviewApprove={() => handleReviewApprove(selectedId)}
            onReviewReject={() => handleReviewReject(selectedId)}
            apiBase={apiBase}
          />
        )}

        {/* Toast */}
        {toast && (
          <div className={`rmp-toast ${toast.kind}`}>{toast.msg}</div>
        )}
      </div>
    </div>
  )
}


// =============================================================================
// Small per-row cells that lazily fetch confidence + validation from the
// detail endpoint. Caches a per-page so subsequent renders don't re-fetch.
// =============================================================================

const detailCache = new Map()

// If the row already carries `pathways` (demo endpoint includes it inline),
// skip the detail fetch. Otherwise fall back to fetching from apiBase — real
// mode uses the summary-only list endpoint and needs an N+1.
function useDetailField(pkg, apiBase) {
  const pkgId = pkg?.id
  const cacheKey = `${apiBase}|${pkgId}`
  const hasInlinePathways = Array.isArray(pkg?.pathways) && pkg.pathways.length > 0

  const [d, setD] = useState(() => {
    if (hasInlinePathways) return pkg
    return detailCache.get(cacheKey)
  })

  useEffect(() => {
    if (hasInlinePathways) { setD(pkg); return }
    if (d || detailCache.has(cacheKey)) return
    let cancelled = false
    fetch(`${apiBase}/${pkgId}`)
      .then(r => r.ok ? r.json() : null)
      .then(j => {
        if (cancelled || !j) return
        detailCache.set(cacheKey, j)
        setD(j)
      })
      .catch(() => {})
    return () => { cancelled = true }
  }, [pkgId, cacheKey, d, hasInlinePathways, pkg, apiBase])
  return d
}

function ConfidenceCell({ pkg, apiBase }) {
  const d = useDetailField(pkg, apiBase)
  const pw = recommendedPathway(d)
  if (!pw?.confidence_score) return <span className="rmp-muted">—</span>
  const tone = confidenceTone(pw.confidence_score)
  return (
    <div className={`rmp-conf-cell ${tone}`}>
      <span className="rmp-conf-num">{pw.confidence_score}%</span>
    </div>
  )
}

function ValidationCell({ pkg, apiBase }) {
  const d = useDetailField(pkg, apiBase)
  const pw = recommendedPathway(d)
  const vm = pw?.validation_metadata
  if (!vm) return <span className="rmp-muted">—</span>
  return <span className={`rmp-validation-pill ${VALIDATION_TONE[vm.status] || 'warn'}`}>{vm.status}</span>
}

function StatusPill({ status }) {
  return <span className={`rmp-status-pill st-${status}`}>{STATUS_LABEL[status] || status}</span>
}


// =============================================================================
// Horizontal Detail Card — replaces the old right-side drawer
// =============================================================================

function DetailDrawer({ pkg, loading, onClose, onApprove, onReject, onReviewApprove, onReviewReject, apiBase }) {
  const pw = recommendedPathway(pkg)
  const vm = pw?.validation_metadata
  const [ticketLoading, setTicketLoading] = useState(false)
  // HITL v2 — review diff loaded lazily when the package is awaiting_review.
  const [reviewDiff, setReviewDiff] = useState(null)
  const [reviewDiffLoading, setReviewDiffLoading] = useState(false)
  // HITL v2 Git-native: separate state for PR info when the package
  // carries a git_pr_url. Sandbox packages never populate this.
  const [gitReviewInfo, setGitReviewInfo] = useState(null)
  const [gitReviewInfoLoading, setGitReviewInfoLoading] = useState(false)
  const isAwaitingReview = pkg?.status === 'awaiting_review'
  const isGitNative = Boolean(pkg?.git_pr_url)
  useEffect(() => {
    if (!isAwaitingReview || !pkg?.id) {
      setReviewDiff(null); setGitReviewInfo(null); return
    }
    let mounted = true
    if (isGitNative) {
      // Git-native: fetch PR info (number, url, live state from GitHub)
      setGitReviewInfoLoading(true)
      fetch(`${apiBase}/${pkg.id}/review-git-info`)
        .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
        .then(data => { if (mounted) setGitReviewInfo(data) })
        .catch(() => { if (mounted) setGitReviewInfo({ error: true }) })
        .finally(() => { if (mounted) setGitReviewInfoLoading(false) })
    } else {
      // Sandbox: fetch the captured unified diff
      setReviewDiffLoading(true)
      fetch(`${apiBase}/${pkg.id}/review-diff`)
        .then(r => r.ok ? r.json() : Promise.reject(new Error(`HTTP ${r.status}`)))
        .then(data => { if (mounted) setReviewDiff(data) })
        .catch(() => { if (mounted) setReviewDiff({ diff: [], error: true }) })
        .finally(() => { if (mounted) setReviewDiffLoading(false) })
    }
    return () => { mounted = false }
  }, [isAwaitingReview, isGitNative, pkg?.id, apiBase])
  const [ticket, setTicket] = useState(() => {
    // If package is ready_for_execution and was approved, check if we already created a ticket
    // (Demo tickets are deterministic: INC + package ID)
    if (pkg?.status === 'ready_for_execution' && pkg?.approved_at) {
      // Check localStorage for demo ticket persistence
      const stored = localStorage.getItem(`ticket_pkg_${pkg.id}`)
      if (stored) return JSON.parse(stored)
    }
    return null
  })
  const [activePath, setActivePath] = useState(0)
  const [localApproved, setLocalApproved] = useState(false)

  // Effective status: if locally approved, treat as ready_for_execution
  const effectiveStatus = localApproved ? 'ready_for_execution' : pkg?.status
  const effectiveTerminal =
    effectiveStatus === 'ready_for_execution' ||
    effectiveStatus === 'rejected' ||
    // Terminal auto-demo + HITL-approved outcomes — SA-4 already ran, there
    // is no decision left to make. Hides the pointless Approve/Reject
    // buttons on packages that are already Fixed / Rolled Back / etc.
    effectiveStatus === 'fixed' ||
    effectiveStatus === 'rolled_back' ||
    effectiveStatus === 'fix_failed' ||
    effectiveStatus === 'review_rejected' ||
    effectiveStatus === 'approved' ||
    effectiveStatus === 'no_fix_needed'

  // Build upgrade steps from pathway remediation_steps
  const allSteps = pw?.remediation_steps?.map((s, i) => ({
    version: `${i + 1}.0.0`,
    action: s.step,
    source: s.source,
    source_url: s.source_url,
    time: '—',
    complexity: i < 2 ? 'Medium' : 'Easy',
    validated: vm?.status === 'validated',
  })) || []

  // WORKAROUND — single compensating control based on family
  const WORKAROUND_BY_FAMILY = {
    os_vulnerability: 'Apply network-level restriction (firewall rule / ACL) to limit exposure until the OS package is upgraded. CVE will continue to be reported but exploitation path is blocked.',
    vulnerable_dependency: 'Pin the dependency to the last known safe version and disable the affected feature path. CVE remains open but attack surface is removed.',
    network_exposure: 'Restrict ingress to known trusted IPs only. The misconfiguration persists but external exploitation is not possible.',
    public_exposure: 'Enable access logging and add a deny-all public access block. Data remains unencrypted but public access is blocked.',
    injection: 'Deploy WAF rule to block the specific attack pattern. Vulnerable code remains but exploitation is prevented at the edge.',
  }

  // STEPPED FIX — minor patch steps (always 2-3 easy steps)
  const STEPPED_BY_FAMILY = {
    os_vulnerability: [
      { action: 'Apply the security patch for the specific CVE (minor version bump, no major upgrade)', complexity: 'Easy', time: '~30 min' },
      { action: 'Restart affected service to load patched library', complexity: 'Easy', time: '~5 min' },
      { action: 'Verify patch applied — run version check and confirm CVE is no longer flagged', complexity: 'Easy', time: '~10 min' },
    ],
    vulnerable_dependency: [
      { action: 'Bump dependency to the nearest patched minor version (e.g. 3.0.0 → 3.0.1)', complexity: 'Easy', time: '~15 min' },
      { action: 'Run test suite to confirm no regressions from the minor bump', complexity: 'Easy', time: '~20 min' },
      { action: 'Deploy to staging and verify functionality', complexity: 'Easy', time: '~30 min' },
    ],
    network_exposure: [
      { action: 'Update the security group to restrict the open port to specific CIDR ranges', complexity: 'Easy', time: '~10 min' },
      { action: 'Apply terraform plan and verify the rule change', complexity: 'Easy', time: '~15 min' },
    ],
    public_exposure: [
      { action: 'Add S3 public access block configuration to the bucket', complexity: 'Easy', time: '~10 min' },
      { action: 'Enable server-side encryption (SSE-S3 default)', complexity: 'Easy', time: '~10 min' },
      { action: 'Apply and verify — confirm bucket is no longer publicly accessible', complexity: 'Easy', time: '~15 min' },
    ],
    injection: [
      { action: 'Add input validation for the affected parameter', complexity: 'Medium', time: '~30 min' },
      { action: 'Deploy the fix and run DAST scan to confirm injection is blocked', complexity: 'Easy', time: '~20 min' },
    ],
  }

  const steppedSteps = (STEPPED_BY_FAMILY[pkg?.family] || STEPPED_BY_FAMILY.os_vulnerability).map((s, i) => ({
    version: `${i + 1}.0.0`,
    action: s.action,
    source: 'Security Best Practice',
    source_url: null,
    time: s.time,
    complexity: s.complexity,
    validated: false,
  }))

  const workaroundStep = [{
    version: '1.0.0',
    action: WORKAROUND_BY_FAMILY[pkg?.family] || 'Apply compensating control to reduce exposure while planning full remediation.',
    source: 'Security Policy',
    source_url: null,
    time: '~15 min',
    complexity: 'Easy',
    validated: false,
  }]

  // 3 path configurations with summaries and overall complexity
  const paths = [
    { steps: allSteps, complexity: allSteps.length > 5 ? 'Complex' : 'Medium', coverage: '100%' },
    { steps: steppedSteps, complexity: 'Easy', coverage: '~80%' },
    { steps: workaroundStep, complexity: 'Easy', coverage: '~40%' },
  ]

  // Summaries per family for each path (2-3 lines each)
  const SUMMARIES = {
    os_vulnerability: {
      direct: 'Full major package upgrade (e.g. OpenSSL 1.1.1 → 3.x). Completely resolves the CVE and hardens the system. Requires service restart and regression testing — schedule during a maintenance window.',
      stepped: 'Minor security patch to the nearest fixed version (e.g. 1.1.1f → 1.1.1j). Addresses this specific CVE with minimal regression risk. Services may need a restart but no breaking changes expected.',
      workaround: 'Adds a network-level restriction (firewall rule / ACL) to block the exploitation path. The CVE will continue to be reported in scans, but the system is not exploitable from external networks.',
    },
    vulnerable_dependency: {
      direct: 'Full dependency upgrade to the latest major version. Resolves all known CVEs in this package and brings in new features. May require code changes if APIs have changed between major versions.',
      stepped: 'Bump to the nearest patched minor release (e.g. 3.0.0 → 3.0.1). Fixes this specific vulnerability with no API changes. Low regression risk — safe to deploy without extensive testing.',
      workaround: 'Pin the dependency to the last known safe version and disable the affected feature/code path. The CVE remains open in scan reports, but the vulnerable function is unreachable at runtime.',
    },
    network_exposure: {
      direct: 'Complete security group reconfiguration — closes all unnecessary open ports and restricts access to documented CIDR ranges. Requires coordination with teams using the affected endpoints.',
      stepped: 'Restrict the specific open port (e.g. SSH/22) to known trusted IP ranges. Leaves other rules unchanged. Quick to apply via terraform and verify.',
      workaround: 'Add monitoring and alerting for connections from untrusted IPs. The misconfiguration persists but any exploitation attempt triggers immediate notification to the security team.',
    },
    public_exposure: {
      direct: 'Full bucket hardening — enables KMS encryption, versioning, access logging, and public access block. Brings the resource into compliance with all relevant CIS/SOC2 controls.',
      stepped: 'Add the S3 public access block and enable default SSE-S3 encryption. Stops public access and encrypts data at rest. Versioning and logging can follow in a separate change.',
      workaround: 'Apply a deny-all bucket policy for public access. Data remains unencrypted and unversioned, but is no longer accessible from outside the AWS account.',
    },
    injection: {
      direct: 'Full code fix — parameterize all queries, sanitize user input, and add output encoding. Resolves the vulnerability at its root. Requires code review and QA cycle.',
      stepped: 'Add input validation for the specific vulnerable parameter identified in the finding. Targeted fix that blocks the known attack vector without refactoring the entire module.',
      workaround: 'Deploy a WAF rule that blocks the specific injection pattern at the edge. Vulnerable code remains unchanged but the attack cannot reach it through normal request flow.',
    },
  }

  const familySummaries = SUMMARIES[pkg?.family] || SUMMARIES.os_vulnerability
  const summaryForPath = [familySummaries.direct, familySummaries.stepped, familySummaries.workaround]

  const steps = paths[activePath]?.steps || allSteps
  const pathComplexity = paths[activePath]?.complexity || 'Medium'

  if (loading || !pkg) {
    return (
      <div className="remediation-detail-overlay" onClick={onClose}>
        <div className="remediation-detail-card horizontal" onClick={(e) => e.stopPropagation()}>
          <div className="detail-card-left" style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
            <div className="rmp-empty">Loading…</div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="remediation-detail-overlay" onClick={onClose}>
      <div className="remediation-detail-card horizontal" onClick={(e) => e.stopPropagation()}>
        {/* Left Section */}
        <div className="detail-card-left">
          <div className="detail-card-header">
            <div className="detail-issue-info">
              <span className="detail-issue-id">#{pkg.id}</span>
              <span className={`detail-severity ${(pkg.family || '').includes('vuln') ? 'high' : 'medium'}`}>
                {FAMILY_LABEL[pkg.family] || pkg.family}
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {pw?.confidence_score && (() => {
                const tone = confidenceTone(pw.confidence_score)
                // Sky-blue filled pill — distinct from every other color on
                // screen: cyan #id pill, orange severity, violet UPGRADE
                // (CHANGE TYPE row), green Fixed. The number inside carries
                // the tone so good/warn/bad reads at a glance.
                // Score number keeps the tone (green/amber/red) so it
                // reads at a glance; the pill itself gets a lighter solid
                // fill (below) so the chip pops against the dark card.
                const numColor = tone === 'good'
                  ? '#86efac'
                  : tone === 'warn'
                    ? '#fde68a'
                    : '#fda4af'
                return (
                  <div
                    className={`rmp-conf-cell ${tone}`}
                    style={{
                      display: 'inline-flex',
                      alignItems: 'center',
                      gap: 10,
                      background: 'rgba(226, 232, 240, 0.1)',
                      border: '1px solid rgba(226, 232, 240, 0.25)',
                      padding: '4px 10px',
                      borderRadius: 4,
                      fontSize: 11,
                      fontWeight: 600,
                      textTransform: 'uppercase',
                      letterSpacing: 0.5,
                      color: '#f1f5f9',
                    }}
                  >
                    Confidence
                    <span
                      className="rmp-conf-num"
                      style={{
                        color: numColor,
                        fontSize: 13,
                        fontWeight: 700,
                        letterSpacing: 0,
                        textTransform: 'none',
                      }}
                    >
                      {pw.confidence_score}%
                    </span>
                  </div>
                )
              })()}
              <StatusPill status={pkg.status} />
            </div>
          </div>

          <div className="detail-meta-grid">
            <div className="detail-meta-item">
              <span className="meta-label">Finding</span>
              <span className="meta-value">{pkg.finding}</span>
            </div>
            <div className="detail-meta-item">
              <span className="meta-label">Root Cause</span>
              <span className="meta-value">{pkg.root_cause}</span>
            </div>
            <div className="detail-meta-row">
              <div className="detail-meta-item">
                <span className="meta-label">Impact</span>
                <span className="meta-value">{pkg.impact}</span>
              </div>
              <div className="detail-meta-item">
                <span className="meta-label">Issue ID</span>
                <span className="meta-value">{pkg.issue_id}</span>
              </div>
            </div>
            <div className="detail-meta-row">
              <div className="detail-meta-item">
                <span className="meta-label">Change Type</span>
                <span className="meta-value change-type">{pkg.family === 'vulnerable_dependency' ? 'UPGRADE' : pkg.family === 'public_exposure' || pkg.family === 'network_exposure' ? 'CONFIG' : pkg.family === 'injection' ? 'CODE_CHANGE' : 'UPGRADE'}</span>
              </div>
              <div className="detail-meta-item">
                <span className="meta-label">Asset Name</span>
                <span className="meta-value change-type">{pkg.asset_name || `asset-${pkg.issue_id}`}</span>
              </div>
            </div>
            <div className="detail-meta-row">
              <div className="detail-meta-item">
                <span className="meta-label">Date Found</span>
                <span className="meta-value">{formatDate(pkg.created_at)}</span>
              </div>
              <div className="detail-meta-item">
                <span className="meta-label">First Detected</span>
                <span className="meta-value">{formatDate(pkg.first_detected || pkg.created_at)}</span>
              </div>
            </div>
            <div className="detail-meta-row">
              <div className="detail-meta-item">
                <span className="meta-label">Created</span>
                <span className="meta-value">{formatDate(pkg.created_at)}</span>
              </div>
              <div className="detail-meta-item">
                <span className="meta-label">Approval</span>
                <span className="meta-value">{APPROVAL_LABEL[pkg.approval_required] || pkg.approval_required}</span>
              </div>
            </div>
          </div>

          {/* Change Detail Table — Before/After format */}
          {pw && (
            <div className="code-diff-container">
              <div className="code-diff-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="17 1 21 5 17 9"></polyline>
                  <path d="M3 11V9a4 4 0 0 1 4-4h14"></path>
                  <polyline points="7 23 3 19 7 15"></polyline>
                  <path d="M21 13v2a4 4 0 0 1-4 4H3"></path>
                </svg>
                <span>Remediation Details</span>
              </div>
              <div className="change-detail-body">
                <table className="change-detail-table">
                  <thead>
                    <tr>
                      <th>Setting</th>
                      <th>Before</th>
                      <th>After</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td className="change-label">Security Coverage</td>
                      <td className="change-before">Vulnerable</td>
                      <td className="change-after">{pw.security_coverage || 'Complete'}</td>
                    </tr>
                    <tr>
                      <td className="change-label">Confidence Score</td>
                      <td className="change-before">—</td>
                      <td className="change-after">{pw.confidence_score || '—'}%</td>
                    </tr>
                    <tr>
                      <td className="change-label">Rollback</td>
                      <td className="change-before">N/A</td>
                      <td className="change-after">{pw.rollback_plan?.supported ? 'Supported' : 'Not Supported'}</td>
                    </tr>
                    {pw.execution_strategy && (
                      <tr>
                        <td className="change-label">Strategy</td>
                        <td className="change-before">Unresolved</td>
                        <td className="change-after">{pw.execution_strategy.slice(0, 60)}…</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Rollback Plan */}
          {pw?.rollback_plan && (
            <div className="code-diff-container">
              <div className="code-diff-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="1 4 1 10 7 10"></polyline>
                  <path d="M3.51 15a9 9 0 1 0 2.13-9.36L1 10"></path>
                </svg>
                <span>Rollback Plan</span>
                <span className={`step-validated-tag ${pw.rollback_plan.supported ? 'validated' : 'not-validated'}`} style={{ marginLeft: 'auto' }}>
                  {pw.rollback_plan.supported ? 'supported' : 'not supported'}
                </span>
              </div>
              <div className="change-detail-body" style={{ maxHeight: 180 }}>
                {pw.rollback_plan.objective && <p style={{ margin: '0 8px 8px', fontSize: 11, color: '#94A3B8', fontStyle: 'italic' }}>{pw.rollback_plan.objective}</p>}
                {pw.rollback_plan.steps?.length > 0 && (
                  <ol style={{ margin: '0 8px', paddingLeft: 18, fontSize: 11, color: '#E2E8F0', lineHeight: 1.7 }}>
                    {pw.rollback_plan.steps.map((s, i) => (
                      <li key={i}>{s.step}</li>
                    ))}
                  </ol>
                )}
                {pw.rollback_plan.limitations?.length > 0 && (
                  <ul style={{ margin: '8px 8px 0', paddingLeft: 18, fontSize: 10, color: '#F59E0B', lineHeight: 1.6 }}>
                    {pw.rollback_plan.limitations.map((x, i) => <li key={i}>{x}</li>)}
                  </ul>
                )}
              </div>
            </div>
          )}

          {/* Validation Tests */}
          {pw?.validation_tests?.length > 0 && (
            <div className="code-diff-container">
              <div className="code-diff-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="9 11 12 14 22 4"></polyline>
                  <path d="M21 12v7a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h11"></path>
                </svg>
                <span>Validation Tests ({pw.validation_tests.length})</span>
              </div>
              <div className="change-detail-body" style={{ maxHeight: 160 }}>
                {pw.validation_tests.map((t, i) => (
                  <div key={i} style={{ padding: '6px 8px', borderBottom: i < pw.validation_tests.length - 1 ? '1px solid #1E293B' : 'none' }}>
                    <div style={{ fontSize: 11, color: '#E2E8F0', fontWeight: 600, marginBottom: 3 }}>{t.name}</div>
                    <pre style={{ margin: 0, fontSize: 10, color: '#6EE7B7', background: '#0B0F19', padding: '4px 6px', borderRadius: 3, whiteSpace: 'pre-wrap' }}>{t.command}</pre>
                    <div style={{ fontSize: 10, color: '#64748B', marginTop: 2 }}>Expected: {t.expected}</div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Test Scripts */}
          {pw?.test_scripts?.length > 0 && (
            <div className="code-diff-container">
              <div className="code-diff-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <polyline points="16 18 22 12 16 6"></polyline>
                  <polyline points="8 6 2 12 8 18"></polyline>
                </svg>
                <span>Test Scripts ({pw.test_scripts.length})</span>
              </div>
              <div className="change-detail-body" style={{ maxHeight: 200 }}>
                {pw.test_scripts.map((ts, i) => (
                  <div key={i} style={{ padding: '6px 8px', borderBottom: i < pw.test_scripts.length - 1 ? '1px solid #1E293B' : 'none' }}>
                    <div style={{ fontSize: 10, color: '#94A3B8', marginBottom: 3 }}>{ts.language} — {ts.description}</div>
                    <pre style={{ margin: 0, fontSize: 10, color: '#6EE7B7', background: '#0B0F19', padding: '6px 8px', borderRadius: 3, whiteSpace: 'pre-wrap', maxHeight: 100, overflow: 'auto' }}>{ts.code}</pre>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Confidence Breakdown */}
          {pw?.confidence_components && (
            <div className="code-diff-container">
              <div className="code-diff-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <path d="M12 20V10"></path>
                  <path d="M18 20V4"></path>
                  <path d="M6 20v-4"></path>
                </svg>
                <span>Confidence: {pw.confidence_score}%</span>
              </div>
              <div className="change-detail-body" style={{ maxHeight: 180 }}>
                <table className="change-detail-table">
                  <thead>
                    <tr>
                      <th>Component</th>
                      <th>Score</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {Object.entries(pw.confidence_components).map(([name, comp]) => (
                      <tr key={name}>
                        <td className="change-label">{name.replace(/_/g, ' ')}</td>
                        <td className="change-after">{comp.score}/{comp.max_score}</td>
                        <td style={{ fontSize: 10, color: '#94A3B8', fontStyle: 'italic' }}>{comp.reason}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Execution Strategy + Advantages/Considerations */}
          {pw?.execution_strategy && (
            <div className="code-diff-container">
              <div className="code-diff-header">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                  <circle cx="12" cy="12" r="10"></circle>
                  <polyline points="12 6 12 12 16 14"></polyline>
                </svg>
                <span>Execution Strategy</span>
              </div>
              <div style={{ padding: '12px 14px' }}>
                <p style={{ margin: 0, fontSize: 12, color: '#E2E8F0', lineHeight: 1.7, whiteSpace: 'pre-wrap' }}>{pw.execution_strategy}</p>

                {(pw.advantages?.length > 0 || pw.considerations?.length > 0) && (
                  <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, marginTop: 14, paddingTop: 12, borderTop: '1px solid #1E293B' }}>
                    {pw.advantages?.length > 0 && (
                      <div style={{ background: 'rgba(16,185,129,0.06)', borderRadius: 6, padding: '10px 12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#10B981" strokeWidth="2.5"><polyline points="20 6 9 17 4 12"></polyline></svg>
                          <span style={{ fontSize: 10, fontWeight: 700, color: '#10B981', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Advantages</span>
                        </div>
                        <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11, color: '#6EE7B7', lineHeight: 1.8, listStyleType: 'none' }}>
                          {pw.advantages.map((x, i) => <li key={i} style={{ position: 'relative', paddingLeft: 10 }}><span style={{ position: 'absolute', left: 0, color: '#10B981' }}>+</span>{x}</li>)}
                        </ul>
                      </div>
                    )}
                    {pw.considerations?.length > 0 && (
                      <div style={{ background: 'rgba(245,158,11,0.06)', borderRadius: 6, padding: '10px 12px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 8 }}>
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#F59E0B" strokeWidth="2.5"><circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line></svg>
                          <span style={{ fontSize: 10, fontWeight: 700, color: '#F59E0B', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Considerations</span>
                        </div>
                        <ul style={{ margin: 0, paddingLeft: 16, fontSize: 11, color: '#FCD34D', lineHeight: 1.8, listStyleType: 'none' }}>
                          {pw.considerations.map((x, i) => <li key={i} style={{ position: 'relative', paddingLeft: 10 }}><span style={{ position: 'absolute', left: 0, color: '#F59E0B' }}>–</span>{x}</li>)}
                        </ul>
                      </div>
                    )}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Validation Metadata Footer */}
          {vm && (
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', padding: '8px 0', borderTop: '1px solid #1E293B', marginTop: 8 }}>
              <span className={`step-validated-tag ${vm.status === 'validated' ? 'validated' : 'not-validated'}`}>
                Validation: {vm.status}
              </span>
              <span style={{ fontSize: 10, color: '#64748B' }}>Confidence: {vm.confidence}</span>
              <span style={{ fontSize: 10, color: '#64748B' }}>{formatDate(vm.timestamp)}</span>
              {vm.sources?.length > 0 && (
                <div style={{ flex: '1 0 100%', fontSize: 10, color: '#94A3B8', marginTop: 4 }}>
                  📖 {vm.sources.join(' · ')}
                </div>
              )}
            </div>
          )}

        </div>

        {/* Right Section — Upgrade Steps */}
        <div className="detail-card-right">
          {/* Close button — top right of card */}
          <div style={{ display: 'flex', justifyContent: 'flex-end', flexShrink: 0 }}>
            <button onClick={onClose} style={{ background: 'none', border: 'none', color: '#64748B', cursor: 'pointer', padding: 2, display: 'flex', alignItems: 'center' }}>
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
              </svg>
            </button>
          </div>

          {/* Path Tabs: Direct Fix, Stepped Fix, Workaround */}
          <div className="path-tabs-container">
            <div className="path-tabs-row">
              {[
                { name: 'Direct Fix', coverage: '100%', description: 'Full remediation in one step' },
                { name: 'Stepped Fix', coverage: '100%', description: 'Incremental remediation' },
                { name: 'Workaround', coverage: '60%', description: 'Mitigates risk without full fix' },
              ].map((path, idx) => (
                <button
                  key={path.name}
                  className={`path-tab ${activePath === idx ? 'active' : ''}`}
                  onClick={() => setActivePath(idx)}
                >
                  {path.name}
                </button>
              ))}
            </div>
            <div className={`path-coverage ${activePath === 2 ? 'partial' : 'full'}`}>
              {summaryForPath[activePath]}
            </div>
          </div>

          <div className="upgrade-steps-section">
            <h4>
              {activePath === 0 ? 'Direct Fix Steps' : activePath === 1 ? 'Stepped Fix' : 'Workaround Steps'}
              <span style={{ marginLeft: 'auto', fontSize: 9, padding: '2px 8px', borderRadius: 4, background: pathComplexity === 'Complex' ? 'rgba(239,68,68,0.15)' : pathComplexity === 'Medium' ? 'rgba(245,158,11,0.15)' : 'rgba(16,185,129,0.15)', color: pathComplexity === 'Complex' ? '#FCA5A5' : pathComplexity === 'Medium' ? '#FCD34D' : '#6EE7B7', fontWeight: 700, textTransform: 'uppercase' }}>
                {pathComplexity}
              </span>
            </h4>
            <div className="upgrade-steps-list">
              {steps.length > 0 ? steps.map((step, index) => (
                <div key={index} className="upgrade-step-item">
                  <div className="step-number">{index + 1}</div>
                  <div className="step-content">
                    <div className="step-version-row">
                      <span className="version-tag">Step {index + 1}</span>
                      {step.source && (
                        <span className="step-time-inline">
                          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                            <polyline points="14 2 14 8 20 8"></polyline>
                          </svg>
                          {step.source}
                        </span>
                      )}
                    </div>
                    <div className="step-action">{step.action}</div>
                  </div>
                </div>
              )) : (
                <div className="rmp-empty" style={{ padding: '24px 12px' }}>No remediation steps available</div>
              )}
            </div>
          </div>

          {/* Confidence score — now lives in the drawer header row (next to
              StatusPill), so the standalone bottom block is no longer needed.
              Kept the ref here as a sentinel in case we want to bring it back. */}

          {/* HITL v2 — Post-fix review panel. Only shown when the package
              is awaiting_review. Two flavors:
                - Git-native: package has git_pr_url → show PR card + link
                - Sandbox: no PR → show captured unified diff */}
          {isAwaitingReview && isGitNative && (
            <div style={{ padding: '16px 0', borderTop: '1px solid #2D3748', marginTop: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12 }}>
                <span style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.06em', color: '#a5b4fc', textTransform: 'uppercase' }}>
                  Post-fix review · Git-native
                </span>
                <span style={{ fontSize: 11, color: '#64748B' }}>
                  Real PR on GitHub. Approve merges it; Reject closes it.
                </span>
              </div>
              {gitReviewInfoLoading ? (
                <div style={{ padding: '18px 12px', color: '#94a3b8', fontSize: 13 }}>Loading PR info…</div>
              ) : gitReviewInfo?.error ? (
                <div style={{ padding: '12px', color: '#f87171', fontSize: 13 }}>Failed to load PR info. Try refresh or check backend logs.</div>
              ) : (
                <div style={{
                  background: '#0b1220', border: '1px solid #1e2a3a', borderRadius: 4,
                  padding: '16px 18px', display: 'grid', gap: 12,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 13, color: '#cbd5e1', fontFamily: 'ui-monospace, SF Mono, Menlo, monospace' }}>
                      🔀 PR #{gitReviewInfo?.pr_number} · <span style={{ color: '#94a3b8' }}>{gitReviewInfo?.repo}</span>
                    </span>
                    <span style={{
                      fontSize: 10.5, fontWeight: 600, letterSpacing: '0.1em', textTransform: 'uppercase',
                      padding: '2px 8px', borderRadius: 3,
                      background: gitReviewInfo?.pr_state_live?.state === 'open' ? '#0f2f2b' : '#2a1d20',
                      color: gitReviewInfo?.pr_state_live?.state === 'open' ? '#5eead4' : '#fda4af',
                      border: `1px solid ${gitReviewInfo?.pr_state_live?.state === 'open' ? '#14b8a6' : '#f87171'}`,
                    }}>
                      {gitReviewInfo?.pr_state_live?.state || gitReviewInfo?.pr_state_cached || 'unknown'}
                    </span>
                    {gitReviewInfo?.pr_state_live?.mergeable === false && (
                      <span style={{ fontSize: 11, color: '#f59e0b' }}>⚠ merge conflict on base branch</span>
                    )}
                  </div>
                  <div style={{ fontSize: 12.5, color: '#94a3b8', fontFamily: 'ui-monospace, SF Mono, Menlo, monospace' }}>
                    Branch: <span style={{ color: '#cbd5e1' }}>{gitReviewInfo?.branch}</span>
                  </div>
                  <a
                    href={gitReviewInfo?.pr_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: 'inline-block', padding: '8px 14px', textDecoration: 'none',
                      background: '#4338CA', color: '#ffffff', borderRadius: 4,
                      fontSize: 13, fontWeight: 500, alignSelf: 'flex-start',
                    }}
                  >
                    View diff on GitHub ↗
                  </a>
                </div>
              )}
            </div>
          )}
          {isAwaitingReview && !isGitNative && (
            <div style={{ padding: '16px 0', borderTop: '1px solid #2D3748', marginTop: '12px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                <span style={{ fontSize: 12, fontWeight: 600, letterSpacing: '0.06em', color: '#5eead4', textTransform: 'uppercase' }}>
                  Post-fix review
                </span>
                <span style={{ fontSize: 11, color: '#64748B' }}>
                  Fix applied &amp; rescan passed. Approve to keep, reject to restore.
                </span>
              </div>
              {reviewDiffLoading ? (
                <div style={{ padding: '18px 12px', color: '#94a3b8', fontSize: 13 }}>Loading diff…</div>
              ) : reviewDiff?.error ? (
                <div style={{ padding: '12px', color: '#f87171', fontSize: 13 }}>Failed to load diff. Fix ran but capture may not have completed.</div>
              ) : (reviewDiff?.diff || []).length === 0 ? (
                <div style={{ padding: '12px', color: '#94a3b8', fontSize: 13 }}>No diff captured. You can still Approve to finalize as Fixed, or Reject to restore from backup.</div>
              ) : (
                reviewDiff.diff.map((d, i) => (
                  <div key={i} style={{ marginBottom: 12 }}>
                    <div style={{ fontSize: 11.5, color: '#94a3b8', fontFamily: 'ui-monospace, SF Mono, Menlo, monospace', marginBottom: 6 }}>
                      📄 {d.file_path} <span style={{ color: '#64748B' }}>· {d.bytes_before} → {d.bytes_after} bytes</span>
                    </div>
                    <pre style={{
                      background: '#0b1220',
                      border: '1px solid #1e2a3a',
                      borderRadius: 4,
                      padding: '12px 14px',
                      fontSize: 12,
                      lineHeight: 1.5,
                      overflow: 'auto',
                      maxHeight: 380,
                      fontFamily: 'ui-monospace, SF Mono, Menlo, Consolas, monospace',
                      margin: 0,
                      whiteSpace: 'pre',
                    }}>
                      {(d.unified_diff || '').split('\n').map((line, li) => {
                        let color = '#cbd5e1'
                        if (line.startsWith('+') && !line.startsWith('+++')) color = '#7dc078'
                        else if (line.startsWith('-') && !line.startsWith('---')) color = '#d17878'
                        else if (line.startsWith('@@')) color = '#64c9c9'
                        else if (line.startsWith('+++') || line.startsWith('---')) color = '#64748B'
                        return <div key={li} style={{ color }}>{line || ' '}</div>
                      })}
                    </pre>
                  </div>
                ))
              )}
            </div>
          )}

          {/* Footer actions */}
          <div className="detail-card-actions">
            {isAwaitingReview ? (
              <>
                <button className="action-btn secondary" onClick={onReviewReject}>Reject Changes</button>
                <button className="action-btn primary create-pr-btn" onClick={onReviewApprove}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                  Approve Changes
                </button>
              </>
            ) : effectiveTerminal ? (
              <>
                {effectiveStatus === 'ready_for_execution' ? (
                  ticket ? (
                    ticket.status === 'created' ? (
                      <a href={ticket.external_ticket_url} target="_blank" rel="noopener noreferrer" className="action-btn primary create-pr-btn" style={{ textDecoration: 'none', textAlign: 'center' }}>
                        🎫 {ticket.external_ticket_id || 'Ticket'} ↗
                      </a>
                    ) : ticket.status === 'failed' ? (
                      <span className="rmp-ticket-error" style={{ flex: 1, textAlign: 'center' }}>⚠ {ticket.error_message}</span>
                    ) : null
                  ) : (
                    <button
                      className="action-btn primary create-pr-btn"
                      disabled={ticketLoading}
                      onClick={async () => {
                        setTicketLoading(true)
                        try {
                          const res = await fetch(
                            `${apiBase}/${pkg.id}/create-ticket`,
                            { method: 'POST', headers: { 'Content-Type': 'application/json' } }
                          )
                          if (!res.ok) {
                            const err = await res.json().catch(() => ({}))
                            throw new Error(err.detail || `HTTP ${res.status}`)
                          }
                          const data = await res.json()
                          setTicket(data)
                          localStorage.setItem(`ticket_pkg_${pkg.id}`, JSON.stringify(data))
                        } catch (e) {
                          setTicket({ status: 'failed', error_message: e.message })
                        } finally {
                          setTicketLoading(false)
                        }
                      }}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <rect x="2" y="7" width="20" height="14" rx="2" ry="2"></rect>
                        <path d="M16 21V5a2 2 0 0 0-2-2h-4a2 2 0 0 0-2 2v16"></path>
                      </svg>
                      {ticketLoading ? 'Creating…' : 'Create Ticket'}
                    </button>
                  )
                ) : effectiveStatus === 'rejected' ? (
                  <span style={{ flex: 1, textAlign: 'center', color: '#e2876f', fontWeight: 600 }}>✗ Rejected</span>
                ) : (
                  // All other terminal states (fixed / rolled_back / fix_failed /
                  // review_rejected / approved / no_fix_needed): show a status
                  // chip in place of the buttons — nothing to decide.
                  // Confidence lives in the drawer header row (not here).
                  <span
                    style={{
                      flex: 1,
                      textAlign: 'center',
                      color:
                        effectiveStatus === 'fixed'
                          ? '#7dc078'
                          : effectiveStatus === 'rolled_back' || effectiveStatus === 'review_rejected'
                            ? '#e2876f'
                            : effectiveStatus === 'fix_failed'
                              ? '#d17878'
                              : '#94a3b8',
                      fontWeight: 600,
                    }}
                  >
                    {effectiveStatus === 'fixed'
                      ? '✓ Fixed'
                      : effectiveStatus === 'rolled_back'
                        ? '↶ Rolled Back'
                        : effectiveStatus === 'fix_failed'
                          ? '✗ Fix Failed'
                          : effectiveStatus === 'review_rejected'
                            ? '✗ Review Rejected'
                            : effectiveStatus === 'no_fix_needed'
                              ? '— No Fix Needed'
                              : effectiveStatus === 'approved'
                                ? '✓ Approved'
                                : effectiveStatus}
                  </span>
                )}
              </>
            ) : (
              <>
                <button className="action-btn secondary" onClick={onReject}>Reject</button>
                <button className="action-btn primary create-pr-btn" onClick={() => { setLocalApproved(true); onApprove(); }}>
                  <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                    <polyline points="20 6 9 17 4 12"></polyline>
                  </svg>
                  Approve
                </button>
              </>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}


function SourceLink({ source, url }) {
  if (!source) return null
  if (url) {
    return <a className="rmp-source" href={url} target="_blank" rel="noopener noreferrer">📖 {source} ↗</a>
  }
  return <span className="rmp-source rmp-source-flat">📖 {source}</span>
}
