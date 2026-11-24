import { useState, useMemo, useEffect, useCallback } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import MultiSelectFilter from '../components/MultiSelectFilter'
import ScannerEndpointModal from '../components/ScannerEndpointModal'
import '../styles/Integrations.css'
import '../styles/AgentModelConfig.css' // reuse .amc-banner-* helpers
import { formatScannerName } from '../lib/scannerName'

// Built-in scanners that always show in "Run a scan" even before any
// custom registration. Anything else added by the user via the modal
// appears here dynamically (driven by /admin/scanners).
const BUILTIN_SCANNERS = [
  { tool: 'osv', label: 'OSV.dev' },
  { tool: 'zap', label: 'OWASP ZAP' },
]


// Catalog cards use namespaced IDs (e.g. "owasp-zap-appsec") but some
// scanners are registered under shorter slugs in connection_registry
// (e.g. "zap"). This map lets the "configured" dot light up for those
// scanners too without forcing a DB rename.
//   key   = catalog id (tool.id in INTEGRATION_CATALOG)
//   value = array of slugs that should also count as "this is configured"
const CATALOG_ID_ALIASES = {
  'owasp-zap-appsec': ['zap', 'owasp-zap'],
  'github-dependabot-appsec': ['dependabot', 'github-dependabot'],
}

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const apiTool = (id, name) => ({
  id,
  name,
  description: `Integrate ${name} to ingest findings and automate workflows.`,
  authType: 'api',
  status: 'disconnected',
  fields: [
    { key: 'apiKey', label: 'API Key', type: 'text' },
    { key: 'secret', label: 'Secret', type: 'password' },
  ],
})

const oauthTool = (id, name) => ({
  id,
  name,
  description: `Connect ${name} using secure OAuth authentication.`,
  authType: 'oauth',
  status: 'disconnected',
  fields: [],
})

const INTEGRATION_CATALOG = [
  { category: 'Application Security', tools: [
    apiTool('burp-suite', 'Burp Suite'),
    apiTool('checkmarx-appsec', 'Checkmarx'),
    oauthTool('dependabot', 'Github Dependabot'),
    oauthTool('hackerone-appsec', 'Hackerone'),
    apiTool('owasp-zap-appsec', 'OWASP ZAP'),
    apiTool('semgrep-ec2', 'Semgrep'),
    apiTool('serverless-ec2', 'Serverless Lab'),
    apiTool('snyk-appsec', 'Snyk'),
    apiTool('sonarqube-appsec', 'SonarQube'),
    apiTool('veracode-appsec', 'Veracode'),
  ]},
  { category: 'Asset Management', tools: [
    oauthTool('aws-asset', 'AWS'),
    oauthTool('jira-asset', 'JIRA'),
    apiTool('jupiterone-asset', 'JupiterOne'),
    oauthTool('oci-asset', 'OCI'),
    apiTool('servicenow-cmdb-asset', 'ServiceNow CMDB'),
  ]},
  { category: 'Cloud Security', tools: [
    apiTool('aws-inspect-cloud', 'AWS Inspect'),
    apiTool('aws-securityhub-cloud', 'AWS Security Hub (CSPM)'),
    apiTool('checkov-ec2', 'Checkov (IaC)'),
    apiTool('crowdstrike-cloud', 'HorizonCSPM (Crowdstrike)'),
    apiTool('grype', 'Anchore Grype'),
    apiTool('paloalto-cloud', 'Prisma Cloud (Palo Alto)'),
    apiTool('tenable-cloud', 'Tenable Cloud Security'),
    apiTool('wiz-cloud', 'Wiz'),
  ]},
  { category: 'Vulnerability Scanners', tools: [
    apiTool('trivy-fs-ec2', 'Trivy (Filesystem)'),
    apiTool('trivy-image-ec2', 'Trivy (Container Image)'),
    apiTool('trivy-image-java-ec2', 'Trivy (Java Image)'),
    apiTool('trivy-image-php-ec2', 'Trivy (PHP Image)'),
    apiTool('trivy-image-python-ec2', 'Trivy (Python Image)'),
    apiTool('trivy-os-ec2', 'Trivy (OS)'),
    apiTool('trivy-os-al2-ec2', 'Trivy (Amazon Linux 2)'),
    apiTool('osv', 'OSV.dev'),
  ]},
  { category: 'DSPM / DLP', tools: [
    apiTool('cyera-dspm', 'Cyera'),
    apiTool('sentra-dspm', 'Sentra'),
    apiTool('symmetry-dspm', 'Symmetry'),
    apiTool('veronous-dspm', 'Varonis'),
  ]},
  { category: 'External Attack Surface Management', tools: [
    apiTool('crowdstrike-easm', 'Falcon Surface (Crowdstrike)'),
    apiTool('cycognito-easm', 'CyCognito'),
    apiTool('microsoft-defender-easm', 'Microsoft Defender'),
  ]},
  { category: 'Non-human Identity', tools: [
    apiTool('entro-nhi', 'Entro Security'),
    apiTool('hush-nhi', 'Hush Security'),
  ]},
  { category: 'Pentest', tools: [
    apiTool('horizon3-pentest', 'Horizon3.ai'),
    apiTool('inspect-pentest', 'Inspective'),
  ]},
  { category: 'SAAS Security', tools: [
    apiTool('appomni-saas', 'AppOmni'),
    apiTool('casb-saas', 'CASB'),
    apiTool('obsidian-saas', 'Obsidian'),
    apiTool('valence-saas', 'Valence'),
  ]},
  { category: 'Security Controls', tools: [
    apiTool('armis-controls', 'Armis'),
    apiTool('safebreach-controls', 'SafeBreach'),
  ]},
  { category: 'Threat Feed', tools: [
    apiTool('cisa-kev-threat', 'CISA KEV'),
    apiTool('epss-threat', 'EPSS'),
    apiTool('euvd-threat', 'EUVD'),
    apiTool('google-ti-threat', 'Google Threat Intelligence'),
    apiTool('mitre-threat', 'MITRE'),
    apiTool('nvd-threat', 'NVD'),
  ]},
  { category: 'Ticketing', tools: [
    oauthTool('azuredevops-ticket', 'Azure DevOps'),
    oauthTool('jira-ticket', 'JIRA'),
    oauthTool('monday-ticket', 'Monday'),
    oauthTool('servicenow-ticket', 'Service Now'),
    oauthTool('slack-ticket', 'Slack'),
    oauthTool('teams-ticket', 'Teams'),
  ]},
  { category: 'Training and Compliance', tools: [
    apiTool('abnormal-training', 'Abnormal'),
    apiTool('adaptive-training', 'Adaptive'),
    apiTool('bugbounty-training', 'Bug Bounty'),
    apiTool('bugcrowd-training', 'Bug Crowd'),
    oauthTool('hackerone-training', 'HackerOne'),
    apiTool('inspective-training', 'Inspective'),
    apiTool('knowbefore-training', 'Knowbe4'),
  ]},
  { category: 'Vulnerability Management', tools: [
    apiTool('qualys-vmdr-vuln', 'Qualys VMDR'),
    apiTool('crowdstrike-vuln', 'Crowdstrike'),
    apiTool('paloalto-vuln', 'Palo Alto'),
    apiTool('rapid7-vuln', 'Rapid7 InsiteVM'),
    apiTool('tenable-nessus-vuln', 'Tenable Nessus'),
  ]},
]

export default function Integrations() {
  const [activeCategory, setActiveCategory] = useState('All')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategories, setSelectedCategories] = useState([])
  const [isFilterOpen, setIsFilterOpen] = useState(false)
  const [selectedTool, setSelectedTool] = useState(null)
  const [integrationsData] = useState(INTEGRATION_CATALOG)

  // Scanner runner panel state
  const [selectedScanners, setSelectedScanners] = useState(new Set())
  const [isTriggering, setIsTriggering] = useState(false)
  const [lastResult, setLastResult] = useState(null)

  // Registered scanners (from /admin/scanners). Used to:
  //  - Show a "configured" dot on integration cards.
  //  - Build the dynamic SCANNERS list in the Run-a-scan card.
  //  - Decide whether the modal renders in "create" or "edit" mode.
  const [registeredScanners, setRegisteredScanners] = useState([])

  // Page-level success toast — surfaced after the modal saves and closes.
  const [toast, setToast] = useState(null)

  useEffect(() => {
    if (!toast) return
    const t = setTimeout(() => setToast(null), 3500)
    return () => clearTimeout(t)
  }, [toast])

  const refreshRegisteredScanners = useCallback(async () => {
    try {
      const res = await fetch(`${API_URL}/admin/scanners`)
      if (!res.ok) return
      const data = await res.json()
      setRegisteredScanners(data.scanners || [])
    } catch {
      // Backend may not be up yet on first paint — fail silently and the
      // BUILTIN_SCANNERS fallback keeps the page functional.
    }
  }, [])

  useEffect(() => {
    refreshRegisteredScanners()
  }, [refreshRegisteredScanners])

  // Merge built-ins with the registered set (registered wins on tool collision).
  // Label resolution: prefer catalog's display name when the slug matches a
  // catalog entry, otherwise fall back to the raw tool slug.
  const SCANNERS = useMemo(() => {
    const catalogNameById = new Map()
    for (const group of INTEGRATION_CATALOG) {
      for (const tool of group.tools) catalogNameById.set(tool.id, tool.name)
    }
    const map = new Map(BUILTIN_SCANNERS.map((s) => [s.tool, s]))
    for (const s of registeredScanners) {
      if (s.enabled) {
        map.set(s.tool, {
          tool: s.tool,
          label: catalogNameById.get(s.tool) || s.tool,
        })
      }
    }
    return Array.from(map.values())
  }, [registeredScanners])

  const registeredByTool = useMemo(() => {
    // Only enabled scanners count as "configured" — disabled rows exist for
    // history/audit but should not light up the green dot.
    const m = new Map()
    for (const s of registeredScanners) {
      if (s.enabled) m.set(s.tool, s)
    }
    return m
  }, [registeredScanners])

  const toggleScanner = (tool) => {
    setSelectedScanners((prev) => {
      const next = new Set(prev)
      if (next.has(tool)) next.delete(tool)
      else next.add(tool)
      return next
    })
  }

  const selectAllScanners = () => {
    setSelectedScanners((prev) =>
      prev.size === SCANNERS.length ? new Set() : new Set(SCANNERS.map((s) => s.tool))
    )
  }

  const handleTrigger = async () => {
    if (selectedScanners.size === 0 || isTriggering) return
    setIsTriggering(true)
    setLastResult(null)

    // Contextual switch: Agents + Remediation pages read this on mount and
    // when they receive the custom event below (fires within the same tab).
    localStorage.setItem('pipelineMode', 'real')
    window.dispatchEvent(new Event('pipelineModeChanged'))

    const eventId = `EVT-UI-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    try {
      const res = await fetch(`${API_URL}/agents/trigger`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eventId,
          action: 'FETCH',
          targets: { scanners: Array.from(selectedScanners) },
        }),
      })
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`)
      }
      const data = await res.json()
      setLastResult({
        ok: true,
        message: `Run triggered (${data.event_id}) — status ${data.status}. Open the Agents page to watch progress.`,
      })
      // Keep the button disabled for an extra 5 seconds after a successful
      // trigger so rapid follow-up clicks can't create duplicate runs.
      setTimeout(() => setIsTriggering(false), 5000)
      return
    } catch (err) {
      setLastResult({ ok: false, message: `Failed to trigger: ${err.message}` })
    }
    setIsTriggering(false)
  }

  // Full end-to-end demo: chains a REAL fetch (into public.*) followed by
  // demo sampling + remediation (into demo.*). Uses the same scanner
  // selection as the Fetch findings button.
  //
  // Sequence:
  //  1. Wipe demo state for a clean slate.
  //  2. Set contextual mode so Agents + Remediation pages auto-switch to demo.
  //  3. POST /agents/trigger_demo with { event_id, action, targets.scanners }.
  //     Backend chains real Master → run_demo_master.
  const handleTriggerDemo = async () => {
    if (selectedScanners.size === 0 || isTriggering) return
    setIsTriggering(true)
    setLastResult(null)

    // Chained flow: real fetch runs FIRST (traces go to public schema, viewable
    // in Real Pipeline mode), then demo sample + remediate runs SECOND (traces
    // go to demo schema, viewable in Demo Pipeline mode). Start in Real mode
    // so the user immediately sees the real fetch. They can toggle to Demo
    // mode once real fetch completes to see the remediation phase.
    localStorage.setItem('pipelineMode', 'real')
    window.dispatchEvent(new Event('pipelineModeChanged'))

    const eventId = `EVT-DEMO-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    try {
      // Cumulative demo: each run accumulates packages in demo schema.
      // No auto-reset — old runs stay so audience sees packages grow across
      // multiple -ec2 scanners. Manual wipe via `POST /agents/demo/reset`
      // or a direct SQL DELETE when a truly fresh state is wanted.
      const res = await fetch(`${API_URL}/agents/trigger_demo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eventId,
          action: 'FULL',
          targets: { scanners: Array.from(selectedScanners) },
        }),
      })
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`)
      }
      const data = await res.json()
      setLastResult({
        ok: true,
        message: `End-to-end demo triggered (${data.event_id}) — real fetch → sample → remediate. Watch the Agents page.`,
      })
      setTimeout(() => setIsTriggering(false), 5000)
      return
    } catch (err) {
      setLastResult({ ok: false, message: `Failed to trigger demo: ${err.message}` })
    }
    setIsTriggering(false)
  }

  // HITL pipeline: same as Run Demo Pipeline but pauses after SA-3 packages
  // land. Cap = 5 per scanner (keeps approval queue reviewable). User
  // approves/rejects each package in the Remediation page; approve triggers
  // Sub-Agent 4 for that single package in the background.
  const handleTriggerHITL = async () => {
    if (selectedScanners.size === 0 || isTriggering) return
    setIsTriggering(true)
    setLastResult(null)

    localStorage.setItem('pipelineMode', 'real')
    window.dispatchEvent(new Event('pipelineModeChanged'))

    const eventId = `EVT-HITL-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    try {
      const res = await fetch(`${API_URL}/agents/trigger_demo_hitl`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eventId,
          action: 'FULL',
          targets: { scanners: Array.from(selectedScanners) },
        }),
      })
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`)
      }
      const data = await res.json()
      setLastResult({
        ok: true,
        message: `HITL pipeline triggered (${data.event_id}) — real fetch → sample (cap 5) → remediate → PAUSED. Approve/Reject packages on the Remediation page.`,
      })
      setTimeout(() => setIsTriggering(false), 5000)
      return
    } catch (err) {
      setLastResult({ ok: false, message: `Failed to trigger HITL: ${err.message}` })
    }
    setIsTriggering(false)
  }

  // HITL v2 — post-fix review. Autonomous dispatch (no pre-fix approval),
  // then SA-4 pauses after successful validate and captures a unified diff
  // of the file it changed. Packages land at `awaiting_review`; user
  // clicks the card to see the diff and Approve or Reject.
  const handleTriggerHITLReview = async () => {
    if (selectedScanners.size === 0 || isTriggering) return
    setIsTriggering(true)
    setLastResult(null)

    localStorage.setItem('pipelineMode', 'real')
    window.dispatchEvent(new Event('pipelineModeChanged'))

    const eventId = `EVT-HITL-REVIEW-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    try {
      const res = await fetch(`${API_URL}/agents/trigger_demo_hitl_review`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eventId,
          action: 'FULL',
          targets: { scanners: Array.from(selectedScanners) },
        }),
      })
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 200)}`)
      }
      const data = await res.json()
      setLastResult({
        ok: true,
        message: `HITL Review pipeline triggered (${data.event_id}) — real fetch → sample → remediate → fix → PAUSED for diff review. Review changes on the Remediation page.`,
      })
      setTimeout(() => setIsTriggering(false), 5000)
      return
    } catch (err) {
      setLastResult({ ok: false, message: `Failed to trigger HITL Review: ${err.message}` })
    }
    setIsTriggering(false)
  }

  // HITL v2 Git-native review (Phase B, side experiment). Autonomous fix,
  // but the "fix" is a real PR opened against the configured GitHub repo.
  // Approve merges the PR; Reject closes it. Requires GITHUB_PAT +
  // GITHUB_REPO in the backend .env. Existing pipelines unaffected.
  const handleTriggerHITLGitReview = async () => {
    if (selectedScanners.size === 0 || isTriggering) return
    setIsTriggering(true)
    setLastResult(null)

    localStorage.setItem('pipelineMode', 'real')
    window.dispatchEvent(new Event('pipelineModeChanged'))

    const eventId = `EVT-HITL-GIT-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    try {
      const res = await fetch(`${API_URL}/agents/trigger_demo_hitl_verified_pr`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          event_id: eventId,
          action: 'FULL',
          targets: { scanners: Array.from(selectedScanners) },
        }),
      })
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`HTTP ${res.status}: ${text.slice(0, 300)}`)
      }
      const data = await res.json()
      setLastResult({
        ok: true,
        message: `HITL Git Review pipeline triggered (${data.event_id}) — fix runs against the configured GitHub repo, opens a real PR per package. Review + merge on the Remediation page.`,
      })
      setTimeout(() => setIsTriggering(false), 5000)
      return
    } catch (err) {
      setLastResult({ ok: false, message: `Failed to trigger HITL Git Review: ${err.message}` })
    }
    setIsTriggering(false)
  }

  const allTools = useMemo(() => {
    return integrationsData.flatMap(group =>
      group.tools.map(tool => ({
        ...tool,
        category: group.category
      }))
    )
  }, [integrationsData])

  const filteredTools = useMemo(() => {
    let base =
      activeCategory === 'All'
        ? allTools
        : integrationsData
          .find(group => group.category === activeCategory)
          ?.tools.map(tool => ({
            ...tool,
            category: activeCategory
          })) || []

    if (activeCategory === 'All' && selectedCategories.length > 0) {
      base = base.filter(tool =>
        selectedCategories.includes(tool.category)
      )
    }

    base = base.filter(tool =>
      tool.name.toLowerCase().includes(searchTerm.toLowerCase())
    )

    return base
  }, [activeCategory, searchTerm, selectedCategories, allTools, integrationsData])

  const categoryOptions = useMemo(() => {
    return integrationsData.map(group => ({
      key: group.category,
      label: group.category,
      count: group.tools.length
    }))
  }, [integrationsData])

  return (
    <>
      <Topbar />
      <div className="app-layout">
        <Sidebar />

        <main className="integrations-page">
          <div className="integrations-header">
            <h1>Integrations</h1>
            <p className="integrations-subtitle">
              Connect with security, compliance, and infrastructure tools
            </p>
          </div>

          <section className="scanner-runner">
            <div className="scanner-runner-header">
              <div>
                <h2>Run a scan</h2>
                <p className="scanner-runner-sub">
                  Select one or more scanners and trigger a normalization run.
                </p>
              </div>
              <button
                type="button"
                className="scanner-runner-link"
                onClick={selectAllScanners}
              >
                {selectedScanners.size === SCANNERS.length ? 'Clear all' : 'Select all'}
              </button>
            </div>

            <div className="scanner-runner-cards">
              {SCANNERS.map((s) => {
                const selected = selectedScanners.has(s.tool)
                return (
                  <button
                    key={s.tool}
                    type="button"
                    className={`scanner-card ${selected ? 'selected' : ''}`}
                    onClick={() => toggleScanner(s.tool)}
                    disabled={isTriggering}
                  >
                    <span className={`scanner-card-check ${selected ? 'checked' : ''}`}>
                      {selected && (
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3">
                          <polyline points="20 6 9 17 4 12"></polyline>
                        </svg>
                      )}
                    </span>
                    <span className="scanner-card-label">{formatScannerName(s.label)}</span>
                    <span className="scanner-card-tool">{formatScannerName(s.tool)}</span>
                  </button>
                )
              })}
            </div>

            <div className="scanner-runner-actions">
              <button
                type="button"
                className="scanner-runner-btn"
                onClick={handleTrigger}
                disabled={selectedScanners.size === 0 || isTriggering}
              >
                {isTriggering
                  ? 'Triggering…'
                  : `Fetch findings${selectedScanners.size ? ` (${selectedScanners.size})` : ''}`}
              </button>
              <button
                type="button"
                className="scanner-runner-btn scanner-runner-btn-demo"
                onClick={handleTriggerDemo}
                disabled={selectedScanners.size === 0 || isTriggering}
                title="End-to-end: real fetch (public.*) → sample 5 per family → remediate (demo.*)"
              >
                {isTriggering
                  ? 'Triggering…'
                  : `Run Demo Pipeline${selectedScanners.size ? ` (${selectedScanners.size})` : ''}`}
              </button>
              <button
                type="button"
                className="scanner-runner-btn scanner-runner-btn-hitl"
                onClick={handleTriggerHITL}
                disabled={selectedScanners.size === 0 || isTriggering}
                title="HITL v1 — pre-fix approval. Real fetch → remediate → PAUSE. Approve/Reject each package to trigger the fix."
              >
                {isTriggering
                  ? 'Triggering…'
                  : `👤 Run HITL Pipeline${selectedScanners.size ? ` (${selectedScanners.size})` : ''}`}
              </button>
              <button
                type="button"
                className="scanner-runner-btn scanner-runner-btn-hitl-review"
                onClick={handleTriggerHITLReview}
                disabled={selectedScanners.size === 0 || isTriggering}
                title="HITL v2 — post-fix review. Autonomous fix, then PAUSE at the diff. Approve keeps the change live; Reject restores the file via SSM."
              >
                {isTriggering
                  ? 'Triggering…'
                  : `🔍 Run HITL Review${selectedScanners.size ? ` (${selectedScanners.size})` : ''}`}
              </button>
              <button
                type="button"
                className="scanner-runner-btn scanner-runner-btn-hitl-git-review"
                onClick={handleTriggerHITLGitReview}
                disabled={selectedScanners.size === 0 || isTriggering}
                title="HITL v2 Git-native — opens real PRs against your configured GitHub repo. Approve merges the PR; Reject closes it. Requires GITHUB_PAT + GITHUB_REPO in .env."
              >
                {isTriggering
                  ? 'Triggering…'
                  : `🔀 Run HITL + Verified PR${selectedScanners.size ? ` (${selectedScanners.size})` : ''}`}
              </button>
              {lastResult && (
                <div
                  className={`scanner-runner-result ${
                    lastResult.ok ? 'success' : 'error'
                  }`}
                >
                  {lastResult.message}
                </div>
              )}
            </div>
          </section>

          <div className="integrations-layout">
            <div className={`integrations-categories ${isFilterOpen ? 'no-scroll' : ''}`}>

              <div className="category-all-row">
                <button
                  className={`category-tab category-tab-all ${activeCategory === 'All' ? 'active' : ''}`}
                  onClick={() => setActiveCategory('All')}
                >
                  <span>All Integrations</span>
                  <span className="category-count">
                    {allTools.length}
                  </span>
                </button>

                <MultiSelectFilter
                  title="Categories"
                  options={categoryOptions}
                  value={selectedCategories}
                  onChange={setSelectedCategories}
                  onOpenChange={setIsFilterOpen}
                />
              </div>

              {integrationsData
                .filter(group =>
                  selectedCategories.length === 0 ||
                  selectedCategories.includes(group.category)
                )
                .map(group => (
                  <button
                    key={group.category}
                    className={`category-tab ${activeCategory === group.category ? 'active' : ''}`}
                    onClick={() => setActiveCategory(group.category)}
                  >
                    <span>{group.category}</span>
                    <span className="category-count">
                      {group.tools.length}
                    </span>
                  </button>
                ))}
            </div>

            <div className="integrations-content-modern">

              <div className="integrations-search-modern">
                <div className="search-input-wrapper">
                  <input
                    type="text"
                    placeholder="Search tools..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                  />

                  {searchTerm && (
                    <button
                      type="button"
                      className="search-clear-btn"
                      onClick={() => setSearchTerm('')}
                    >
                      <svg
                        width="14"
                        height="14"
                        viewBox="0 0 24 24"
                        stroke="currentColor"
                        fill="none"
                        strokeWidth="2"
                      >
                        <line x1="18" y1="6" x2="6" y2="18" />
                        <line x1="6" y1="6" x2="18" y2="18" />
                      </svg>
                    </button>
                  )}
                </div>
              </div>

              <div className="integration-grid-modern">
                {filteredTools.map(tool => {
                  const aliases = CATALOG_ID_ALIASES[tool.id] || []
                  const configured =
                    registeredByTool.has(tool.id) ||
                    aliases.some((slug) => registeredByTool.has(slug))
                  return (
                    <div
                      key={tool.id}
                      className="integration-card-modern"
                      onClick={() => setSelectedTool(tool)}
                      style={{ position: 'relative' }}
                    >
                      {configured && (
                        <span
                          className="integration-configured-dot"
                          title="Endpoint configured"
                        />
                      )}
                      <div className="integration-card-name">
                        {tool.name}
                      </div>

                      {searchTerm && (
                        <div className="integration-category-badge">
                          {tool.category}
                        </div>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        </main>
      </div>

      {selectedTool && (
        <ScannerEndpointModal
          tool={selectedTool}
          existing={registeredByTool.get(selectedTool.id) || null}
          onClose={() => setSelectedTool(null)}
          onSaved={(message) => {
            setToast({ kind: 'ok', message })
            refreshRegisteredScanners()
          }}
        />
      )}

      {toast && (
        <div className={`integrations-toast integrations-toast-${toast.kind}`} role="status">
          <span className="integrations-toast-icon" aria-hidden>
            {toast.kind === 'ok' ? '✓' : '!'}
          </span>
          <span>{toast.message}</span>
          <button
            className="integrations-toast-close"
            onClick={() => setToast(null)}
            aria-label="Dismiss"
          >
            ×
          </button>
        </div>
      )}
    </>
  )
}
