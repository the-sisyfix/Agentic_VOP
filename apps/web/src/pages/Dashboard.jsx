import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import { useDashboardData } from '../hooks/useDashboardData'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'

import '../styles/Dashboard.css'

const ActivityIcon = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </svg>
)

export default function Dashboard() {
  const [showCveTicker] = useState(true)
  const [riskReducedRange, setRiskReducedRange] = useState('14d')

  const { stats, latestCves, topRiskDrivers, chartData, exposureMap } =
    useDashboardData(riskReducedRange)

  const { Critical = 0, High = 0, Medium = 0 } = stats.severityBreakdown || {}

  const statCards = [
    {
      title: 'Risk Exposure',
      value: stats.total,
      delta: stats.todayAdded,
      previousTotal: stats.previousTotal,
      details: null, // custom render below
      severityBadges: { Critical, High, Medium },
    },
    {
      title: 'Requiring Action',
      value: stats.requiringAction,
      details: null,
      actionBadges: { Critical, High },
    },
    {
      title: 'Ready-to-Remediate',
      value: stats.readyToRemediate,
      details: 'With AI-suggested fix',
    },
    {
      title: 'Validated',
      value: stats.validated ?? '—',
      details: stats.avgConfidence ? `Avg confidence: ${stats.avgConfidence}%` : 'No confidence data yet',
      hasConfidence: !!stats.avgConfidence,
    },
    {
      title: 'Remediated',
      value: stats.remediated ?? '—',
      details: stats.avgMttr ? `MTTR: ${stats.avgMttr}` : 'MTTR: not enough data',
      hasMttr: !!stats.avgMttr,
    },
  ]

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />
        <main className="dashboard-main dashboard-dark">
          <div className="stat-cards-row">
            {statCards.map((card, index) => (
              <div key={index} className="stat-card">
                <div className="stat-card-title">{card.title}</div>
                <div className="stat-card-body">
                  <span className="stat-card-value">{card.value}</span>
                  {card.delta > 0 && (
                    <span className="stat-delta-badge" title={`Was ${card.previousTotal} before today. +${card.delta} added on ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`}>
                      +{card.delta}
                    </span>
                  )}
                </div>
                {card.severityBadges ? (
                  <div className="stat-card-details severity-badges">
                    <span className="sev-badge critical">{card.severityBadges.Critical} C</span>
                    <span className="sev-badge high">{card.severityBadges.High} H</span>
                    <span className="sev-badge medium">{card.severityBadges.Medium} M</span>
                  </div>
                ) : card.actionBadges ? (
                  <div className="stat-card-details severity-badges">
                    <span className="sev-badge critical">{card.actionBadges.Critical} C</span>
                    <span className="sev-badge high">{card.actionBadges.High} H</span>
                  </div>
                ) : (
                  <div className={`stat-card-details ${card.hasMttr ? 'mttr-badge' : ''} ${card.hasConfidence ? 'confidence-badge' : ''}`}>{card.details}</div>
                )}
              </div>
            ))}
          </div>

          {showCveTicker && <CVETicker cves={latestCves} />}

          <div className="dashboard-grid">
            <TopRiskDrivers data={topRiskDrivers} />
            <RiskReduced
              chartData={chartData}
              timeRange={riskReducedRange}
              setTimeRange={setRiskReducedRange}
            />
          </div>

          <div className="exposure-map-card">
            <div className="exposure-map-header">
              <h2>Exposure Map</h2>
            </div>

            {/* Row 1 — Context: what is this asset */}
            <div className="exposure-map-row-label">Asset Context</div>
            <div className="exposure-map-grid">
              <ExposureCardCompact
                icon="internet"
                title="Internet Facing"
                subtitle="Public-exposed assets"
                mainValue={exposureMap.internetFacing.assetCount}
                mainLabel={
                  exposureMap.internetFacing.assetCount === 1 ? 'asset' : 'assets'
                }
                bucket={exposureMap.internetFacing}
              />
              <ExposureCardCompact
                icon="crown"
                title="Crown Jewel Apps"
                subtitle="Business-critical (≥4)"
                mainValue={exposureMap.crownJewel.assetCount}
                mainLabel={
                  exposureMap.crownJewel.assetCount === 1 ? 'asset' : 'assets'
                }
                bucket={exposureMap.crownJewel}
              />
              <RegulatoryComplianceCard data={exposureMap.regulatory} />
            </div>

            {/* Row 2 — 3 threat-angle cards. "Threat Based" is the
                external-reachable angle (renamed from "Internet Zone" to
                avoid lexical clash with the Row 1 "Internet Facing" card).
                Priority: Threat Based > Extranet > Intranet. */}
            <div className="exposure-map-row-label">
              Threat Based
              <span className="exposure-map-row-hint">
                {' '}— priority: Threat &gt; Extranet &gt; Intranet
              </span>
            </div>
            <div className="exposure-map-grid">
              <ExposureCardCompact
                icon="threat"
                title="Threat Based"
                subtitle="External attacker reach"
                mainValue={exposureMap.zoneInternet.assetCount}
                mainLabel={
                  exposureMap.zoneInternet.assetCount === 1 ? 'asset' : 'assets'
                }
                bucket={exposureMap.zoneInternet}
              />
              <ExposureCardCompact
                icon="extranet"
                title="Extranet"
                subtitle="Partner / customer-reachable"
                mainValue={exposureMap.zoneExtranet.assetCount}
                mainLabel={
                  exposureMap.zoneExtranet.assetCount === 1 ? 'asset' : 'assets'
                }
                bucket={exposureMap.zoneExtranet}
              />
              <ExposureCardCompact
                icon="intranet"
                title="Intranet"
                subtitle="Internal-only access"
                mainValue={exposureMap.zoneIntranet.assetCount}
                mainLabel={
                  exposureMap.zoneIntranet.assetCount === 1 ? 'asset' : 'assets'
                }
                bucket={exposureMap.zoneIntranet}
              />
            </div>
          </div>
        </main>
      </div>
    </>
  )
}

function CVETicker({ cves }) {
  if (!cves || cves.length === 0) return null
  // Duplicate the list so the CSS marquee (translateX 0 → -50%) loops
  // seamlessly — when the first copy scrolls off the left, the second
  // copy is already taking its place on the right.
  const loopedCves = [...cves, ...cves]
  return (
    <div className="cve-ticker-wrapper">
      <div className="cve-ticker-label">
        <span className="ticker-icon"><ActivityIcon /></span>
        <span>Latest CVEs</span>
      </div>
      <div className="cve-ticker-container">
        <div className="cve-ticker-track">
          {loopedCves.map((cve, index) => (
            <div
              key={cve.id + '-' + index}
              className={
                'cve-ticker-item severity-' + (cve.severity || '').toLowerCase()
              }
            >
              <span className="severity-dot"></span>
              <span className="cve-id">{cve.id}</span>
              <span className="cve-count">({cve.count})</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function TopRiskDrivers({ data = [] }) {
  const navigate = useNavigate()
  const [viewMode, setViewMode] = useState('issues')

  const handleViewIssues = (item) => {
    navigate(`/issues?search=${encodeURIComponent(item.cve)}`)
  }

  const handleViewAssets = (item) => {
    navigate(`/assets?asset_id=${encodeURIComponent(item.asset_id)}`)
  }

  const getRiskScoreClass = (score) => {
    if (score >= 90) return 'critical'
    if (score >= 70) return 'high'
    if (score >= 50) return 'medium'
    return 'low'
  }

  return (
    <div className="risk-drivers-card">
      <div className="risk-drivers-header">
        <div className="header-left">
          <h2>Top Risk Drivers</h2>
          <span className="subtitle">Ranked by derived risk score</span>
        </div>
        <div className="view-toggle-box">
          <div
            className={`toggle-option ${viewMode === 'issues' ? 'active' : ''}`}
            onClick={() => setViewMode('issues')}
          >
            Issues
          </div>
          <div
            className={`toggle-option ${viewMode === 'assets' ? 'active' : ''}`}
            onClick={() => setViewMode('assets')}
          >
            Assets
          </div>
        </div>
      </div>

      {data.length === 0 ? (
        <div style={{ padding: '2rem', textAlign: 'center' }}>
          <p style={{ color: 'var(--dash-text-secondary)' }}>No risk drivers yet</p>
        </div>
      ) : (
        <div className="risk-drivers-table">
          <div className="risk-table-wrapper">
            <table className="risk-table">
              <thead>
                <tr>
                  <th>{viewMode === 'issues' ? 'CVE' : 'Asset'}</th>
                  <th>Risk Score</th>
                  <th>Impact</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {data.map((item) => (
                  <tr key={item.cve || item.asset_id || item.id}>
                    <td className="col-name" title={item.name}>
                      <div className="cve-info">
                        <span className="cve-title">{item.name}</span>
                        <span className="cve-meta">
                          {item.criticals > 0 && (
                            <span className="severity-badge critical">{item.criticals} Critical</span>
                          )}
                          {item.high > 0 && (
                            <span className="severity-badge high">{item.high} High</span>
                          )}
                        </span>
                      </div>
                    </td>
                    <td className="col-score">
                      <div className="risk-score-container">
                        <span className={`risk-score-value ${getRiskScoreClass(item.avg_risk_score)}`}>
                          {item.avg_risk_score}
                        </span>
                      </div>
                    </td>
                    <td className="col-impact">
                      <div className="impact-metrics">
                        <div className="impact-main">
                          {viewMode === 'issues' ? item.total_affected : item.criticals}
                        </div>
                        <div className="impact-details">
                          <span>
                            {viewMode === 'issues'
                              ? item.total_affected === 1
                                ? 'issue'
                                : 'issues'
                              : item.criticals === 1
                                ? 'critical CVE'
                                : 'critical CVEs'}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td className="col-action">
                      <button
                        className="fix-plan-btn"
                        onClick={() =>
                          viewMode === 'issues' ? handleViewIssues(item) : handleViewAssets(item)
                        }
                      >
                        {viewMode === 'issues' ? 'View Issues' : 'View Assets'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="risk-drivers-footer">
        <div className="risk-legend">
          <span className="legend-item"><span className="legend-dot critical"></span>90+ Critical Risk</span>
          <span className="legend-item"><span className="legend-dot high"></span>70+ High Risk</span>
          <span className="legend-item"><span className="legend-dot medium"></span>50+ Medium Risk</span>
        </div>
      </div>
    </div>
  )
}

function RiskReduced({ chartData = [], timeRange = '14d', setTimeRange = () => {} }) {
  const [topFixes] = useState([])

  return (
    <div className="risk-reduced-card">
      <div className="risk-reduced-header">
        <h2>
          Risk Reduced{' '}
          <span className="time-period">
            ({timeRange === '14d' ? 'Last 14 days' : timeRange === '30d' ? 'Last 30 days' : 'Last 3 months'})
          </span>
        </h2>
        <div className="risk-reduced-toggles">
          {['14d', '30d', '90d'].map((range) => (
            <button
              key={range}
              className={`toggle-option ${timeRange === range ? 'active' : ''}`}
              onClick={() => setTimeRange(range)}
            >
              {range === '14d' ? '14D' : range === '30d' ? '30D' : '3M'}
            </button>
          ))}
        </div>
      </div>

      <div className="risk-reduced-chart">
        <ResponsiveContainer width="100%" height={160}>
          <AreaChart data={chartData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="#1E293B" vertical={false} />
            <XAxis dataKey="day" stroke="#334155" tick={{ fill: '#64748B', fontSize: 10 }} axisLine={false} tickLine={false} />
            <YAxis
              stroke="#334155"
              tick={{ fill: '#64748B', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              width={45}
              tickFormatter={(value) => (value >= 1000 ? `${Math.round(value / 1000)}k` : value)}
            />
            <Tooltip contentStyle={{ background: '#151C2C', border: '1px solid #334155', borderRadius: '8px', color: '#fff' }} />
            <Area type="monotone" dataKey="exposure" stroke="#ef4444" fillOpacity={0.15} />
            <Area type="monotone" dataKey="remediated" stroke="#10b981" fillOpacity={0.15} />
            <Area type="monotone" dataKey="validated" stroke="#3b82f6" fillOpacity={0.15} />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      <div className="chart-legend">
        <div className="legend-item"><span className="legend-dot red"></span><span>Exposure</span></div>
        <div className="legend-item"><span className="legend-dot green"></span><span>Remediated</span></div>
        <div className="legend-item"><span className="legend-dot blue"></span><span>Validated</span></div>
      </div>

      <div className="top-fixes-section">
        <h3>Top fixes that reduced most risk</h3>
        {topFixes.length === 0 ? (
          <p style={{ color: 'var(--dash-text-secondary)', fontSize: '0.85rem' }}>No data yet</p>
        ) : (
          topFixes.map((fix, index) => (
            <div key={index} className="top-fix-item">
              <span className="fix-indicator"></span>
              <span className="fix-name">{fix.name}</span>
              <div className="fix-bar">
                <div className="fix-bar-fill" style={{ width: `${(fix.count / 400) * 100}%` }}></div>
              </div>
              <span className="fix-count">{fix.count}</span>
              {fix.automated && <span className="fix-badge">Automation</span>}
            </div>
          ))
        )}
      </div>
    </div>
  )
}

function ExposureCardCompact({ icon, title, subtitle, mainValue, mainLabel, bucket }) {
  const renderIcon = () => {
    if (icon === 'internet') {
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="10" />
          <line x1="2" y1="12" x2="22" y2="12" />
          <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
        </svg>
      )
    }
    if (icon === 'crown') {
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M2 17l3-11 5 5 2-8 2 8 5-5 3 11H2z" />
          <path d="M2 17h20v4H2z" />
        </svg>
      )
    }
    if (icon === 'extranet') {
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <circle cx="12" cy="12" r="9" />
          <path d="M3 12h18" />
          <path d="M12 3v18" />
          <path d="M6 6l12 12" />
        </svg>
      )
    }
    if (icon === 'intranet') {
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="3" y="6" width="18" height="12" rx="2" />
          <line x1="8" y1="12" x2="16" y2="12" />
        </svg>
      )
    }
    if (icon === 'threat') {
      return (
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <path d="M12 2L3 7v6c0 5 4 9 9 10 5-1 9-5 9-10V7l-9-5z" />
          <path d="M9 12l2 2 4-4" />
        </svg>
      )
    }
    return null
  }

  const findingCount = bucket?.findingCount ?? 0
  const critical = bucket?.critical ?? 0
  const high = bucket?.high ?? 0
  const medium = bucket?.medium ?? 0

  return (
    <div className="exposure-compact">
      <div className="exposure-compact-header">
        <div className="exposure-compact-icon">{renderIcon()}</div>
        <div className="exposure-compact-content">
          <span className="exposure-compact-title">{title}</span>
          <span className="exposure-compact-subtitle">{subtitle}</span>
        </div>
      </div>

      {/* Right-aligned stack: value, finding count, severity proportion bar */}
      <div className="exposure-compact-strip">
        <span className="exposure-compact-strip-primary">
          <span className="value-number">{mainValue}</span>
          {mainLabel && <span className="value-label">{mainLabel}</span>}
        </span>
        <span className="exposure-finding-count">
          {findingCount} {findingCount === 1 ? 'finding' : 'findings'}
        </span>
        <SeverityBar critical={critical} high={high} medium={medium} />
      </div>
    </div>
  )
}

// Stacked horizontal bar showing the C/H/M severity proportion of the card's
// findings. Always renders all three labels so the user can read the counts
// even when a severity has zero findings (the bar segment just stays empty).
function SeverityBar({ critical = 0, high = 0, medium = 0 }) {
  const total = critical + high + medium
  const cPct = total > 0 ? (critical / total) * 100 : 0
  const hPct = total > 0 ? (high / total) * 100 : 0
  const mPct = total > 0 ? (medium / total) * 100 : 0

  return (
    <div className="severity-bar">
      <div className="severity-bar-track">
        {critical > 0 && (
          <div
            className="seg seg-critical"
            style={{ width: `${cPct}%` }}
            title={`Critical: ${critical}`}
          />
        )}
        {high > 0 && (
          <div className="seg seg-high" style={{ width: `${hPct}%` }} title={`High: ${high}`} />
        )}
        {medium > 0 && (
          <div
            className="seg seg-medium"
            style={{ width: `${mPct}%` }}
            title={`Medium: ${medium}`}
          />
        )}
      </div>
      <div className="severity-bar-legend">
        <span className="sb-leg sb-critical">
          <span className="sb-dot" />C {critical}
        </span>
        <span className="sb-leg sb-high">
          <span className="sb-dot" />H {high}
        </span>
        <span className="sb-leg sb-medium">
          <span className="sb-dot" />M {medium}
        </span>
      </div>
    </div>
  )
}

function RegulatoryComplianceCard({ data }) {
  const findingCount = data?.findingCount ?? 0
  const critical = data?.critical ?? 0
  const high = data?.high ?? 0
  const medium = data?.medium ?? 0
  const totalAssets = data?.assetCount ?? 0

  return (
    <div className="exposure-compact regulatory">
      <div className="exposure-compact-header">
        <div className="exposure-compact-icon compliance">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
            <path d="M9 12l2 2 4-4" />
          </svg>
        </div>
        <div className="exposure-compact-content">
          <span className="exposure-compact-title">Regulatory Impact</span>
          <span className="exposure-compact-subtitle">Compliance scope at risk</span>
        </div>
      </div>

      <div className="exposure-compact-strip">
        <span className="exposure-compact-strip-primary">
          <span className="value-number">{totalAssets ?? '—'}</span>
          <span className="value-label">{totalAssets === 1 ? 'asset' : 'assets'}</span>
        </span>
        <span className="exposure-finding-count">
          {findingCount} {findingCount === 1 ? 'finding' : 'findings'}
        </span>
        <SeverityBar critical={critical} high={high} medium={medium} />
      </div>
    </div>
  )
}
