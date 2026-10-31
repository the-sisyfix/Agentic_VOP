import { useEffect, useMemo, useState } from 'react'
import Topbar from '../components/Topbar'
import Sidebar from '../components/Sidebar'
import AgentModelConfig from '../components/AgentModelConfig'
import { supabase } from '../lib/supabase'
import '../styles/Agents.css'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
const DEMO_POLL_MS = 2000

const ROLE_OPTIONS = [
  { key: 'all', label: 'All' },
  { key: 'master', label: 'Master' },
  { key: 'sub', label: 'Sub-agents' },
]

const EVENT_OPTIONS = [
  { key: 'all', label: 'All events' },
  { key: 'dispatch', label: 'Task dispatch' },
  { key: 'message', label: 'Message' },
  { key: 'result', label: 'Result' },
  { key: 'error', label: 'Error' },
]

const EVENT_TYPE_MAP = {
  DISPATCH: 'dispatch',
  DONE: 'result',
  MESSAGE: 'message',
  ERROR: 'error',
}

function deriveTo(row) {
  if (row.event_type === 'DISPATCH' && row.payload?.sub_agent_id) {
    return row.payload.sub_agent_id
  }
  if (row.event_type === 'DONE' || row.event_type === 'ERROR') {
    return 'master'
  }
  return null
}

function mapTraceRow(row) {
  return {
    id: row.id,
    from: row.agent,
    fromName: row.agent,
    to: deriveTo(row),
    toName: deriveTo(row),
    type: EVENT_TYPE_MAP[row.event_type] || 'message',
    taskId: row.payload?.correlation_id || null,
    message: row.message,
    timestamp: row.created_at,
    durationMs: row.payload?.duration_ms ?? null,
    payload: row.payload,
    runId: row.run_id,
  }
}

export default function Agents() {
  const [traceEvents, setTraceEvents] = useState([])
  const [runs, setRuns] = useState([])
  const [selectedAgent, setSelectedAgent] = useState('all')
  const [selectedEventType, setSelectedEventType] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedTrace, setSelectedTrace] = useState(null)
  const [autoScroll, setAutoScroll] = useState(true)
  const [modelConfigOpen, setModelConfigOpen] = useState(false)
  // env2 reset state — buttons next to Real/Demo toggle
  // `resettingLabel` holds the label of the button currently running (e.g.
  // 'CSPM'). Only that button shows the spinner; the others stay disabled
  // but keep their normal label so the UI is clear about which reset is in
  // flight. null when no reset is running.
  const [resettingLabel, setResettingLabel] = useState(null)
  const resetting = resettingLabel !== null
  const [resetToast, setResetToast] = useState(null)  // { kind: 'success'|'error', message: string }
  // env2 busy state — poll /admin/env2/status so reset buttons can disable
  // themselves when a fix_run is active (would race with SSM). Poll cadence
  // is 10s so the UI updates within one iteration of the fix loop.
  const [env2Busy, setEnv2Busy] = useState(null)  // null (unknown) | Env2StatusResponse
  useEffect(() => {
    let mounted = true
    const poll = async () => {
      try {
        const r = await fetch(`${API_URL}/admin/env2/status`)
        if (!mounted || !r.ok) return
        const d = await r.json()
        if (mounted) setEnv2Busy(d)
      } catch { /* transient network error */ }
    }
    poll()
    const interval = setInterval(poll, 10000)
    return () => { mounted = false; clearInterval(interval) }
  }, [])
  // Contextual switch: 'real' (supabase realtime on public.*) or 'demo' (poll
  // backend demo endpoints). Set by Integrations page's trigger buttons; can
  // be overridden manually via the pill at the top of the page.
  const [pipelineMode, setPipelineMode] = useState(
    () => localStorage.getItem('pipelineMode') || 'real'
  )

  // Listen for pipelineMode changes from other components (Integrations page)
  // and from other tabs (native `storage` event).
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

  useEffect(() => {
    let mounted = true

    // Clear both lists when switching modes so demo/real never bleed into each other.
    setTraceEvents([])
    setRuns([])
    setSelectedTrace(null)

    if (pipelineMode === 'demo') {
      // ----- Demo mode: poll backend endpoints (no realtime on demo schema) -----
      const poll = async () => {
        try {
          const runsRes = await fetch(`${API_URL}/agents/demo/runs`)
          if (!mounted || !runsRes.ok) return
          const runsData = await runsRes.json()
          if (!mounted) return
          const demoRuns = runsData.runs || []
          setRuns(demoRuns)

          // Fetch traces for ALL demo runs so the trace stream shows every run.
          const allTraces = []
          for (const r of demoRuns.slice(0, 5)) {
            try {
              const tRes = await fetch(`${API_URL}/agents/demo/runs/${r.run_id}/traces`)
              if (!tRes.ok) continue
              const tData = await tRes.json()
              allTraces.push(...(tData.traces || []))
            } catch { /* skip this run's traces */ }
          }
          if (!mounted) return
          // Sort DESC (newest first) to match real-mode display.
          allTraces.sort((a, b) => new Date(b.created_at) - new Date(a.created_at))
          setTraceEvents(allTraces.map(mapTraceRow))
        } catch { /* transient network error, retry next tick */ }
      }
      poll()
      const interval = setInterval(poll, DEMO_POLL_MS)
      return () => {
        mounted = false
        clearInterval(interval)
      }
    }

    // ----- Real mode: existing supabase realtime on public.* (unchanged) -----
    supabase
      .from('agent_trace_events')
      .select('*')
      .order('created_at', { ascending: false })
      .limit(200)
      .then(({ data, error }) => {
        if (!mounted || error || !data) return
        setTraceEvents(data.map(mapTraceRow))
      })

    const traceChannel = supabase
      .channel('agent-trace-stream')
      .on(
        'postgres_changes',
        { event: 'INSERT', schema: 'public', table: 'agent_trace_events' },
        (payload) => {
          if (!mounted) return
          setTraceEvents((prev) => [mapTraceRow(payload.new), ...prev])
        }
      )
      .subscribe()

    supabase
      .from('agent_runs')
      .select('*')
      .order('started_at', { ascending: false })
      .limit(100)
      .then(({ data, error }) => {
        if (!mounted || error || !data) return
        setRuns(data)
      })

    const runsChannel = supabase
      .channel('agent-runs-stream')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'agent_runs' },
        (payload) => {
          if (!mounted) return
          if (payload.eventType === 'INSERT') {
            setRuns((prev) => [payload.new, ...prev])
          } else if (payload.eventType === 'UPDATE') {
            setRuns((prev) =>
              prev.map((r) => (r.run_id === payload.new.run_id ? payload.new : r))
            )
          }
        }
      )
      .subscribe()

    return () => {
      mounted = false
      supabase.removeChannel(traceChannel)
      supabase.removeChannel(runsChannel)
    }
  }, [pipelineMode])

  const setModeManual = (mode) => {
    localStorage.setItem('pipelineMode', mode)
    window.dispatchEvent(new Event('pipelineModeChanged'))
  }

  // Shared runner for all 4 lab-reset buttons. `resetting` is a single flag
  // that blocks ALL reset buttons while any one is running — env2 is a shared
  // sandbox so overlapping resets would race on the same host.
  const runReset = async ({ label, endpoint, confirmMsg, successFmt }) => {
    if (resetting) return
    if (confirmMsg && !window.confirm(confirmMsg)) return
    setResettingLabel(label)
    setResetToast(null)
    // Hard-cap the request so a stuck backend / dead network can never
    // leave the button spinning forever. 10 min covers every reset flow
    // (longest is Images at ~3-5 min) with plenty of buffer.
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 10 * 60 * 1000)
    try {
      const res = await fetch(`${API_URL}${endpoint}`, {
        method: 'POST',
        signal: controller.signal,
      })
      const body = await res.json().catch(() => ({}))
      if (!res.ok) {
        const detail = typeof body?.detail === 'string'
          ? body.detail
          : JSON.stringify(body?.detail || body)
        setResetToast({ kind: 'error', message: `${label} reset failed: ${detail.slice(0, 300)}` })
      } else {
        setResetToast({
          kind: 'success',
          message: successFmt ? successFmt(body) : `✅ ${label} reset — ready`,
        })
      }
    } catch (e) {
      const msg = e.name === 'AbortError'
        ? `${label} reset timed out after 10 min — backend unresponsive. Check the server logs.`
        : `${label} reset request failed: ${e.message || e}`
      setResetToast({ kind: 'error', message: msg })
    } finally {
      clearTimeout(timeoutId)
      setResettingLabel(null)
    }
  }

  const handleResetCSPM = () => runReset({
    label: 'CSPM',
    endpoint: '/admin/env2/reset',
    confirmMsg:
      'Reset CSPM lab (checkov-ec2) to the vulnerable baseline?\n\n' +
      'This will:\n' +
      '  • terraform destroy the current lab resources\n' +
      '  • wipe S3 terraform state + DynamoDB lock\n' +
      '  • restore main.tf from the pristine template\n' +
      '  • terraform apply the fresh vulnerable baseline\n\n' +
      'Takes ~60 seconds. Do not trigger a demo run during this.',
    successFmt: (body) => {
      const bits = []
      if (body.checkov_failed != null) bits.push(`${body.checkov_failed} checkov failures`)
      if (body.new_sg_id) bits.push(`new SG ${body.new_sg_id}`)
      if (body.duration_s != null) bits.push(`${body.duration_s}s`)
      return `✅ CSPM reset — ${bits.join(' · ') || 'ready'}`
    },
  })

  const handleResetImages = () => runReset({
    label: 'Images',
    endpoint: '/admin/env2/reset-images',
    confirmMsg:
      'Reset all 3 image labs (infra + java + python) to their vulnerable baseline?\n\n' +
      'Covers scanners: trivy-image-ec2, trivy-image-java-ec2, trivy-image-python-ec2.\n\n' +
      'Rebuilds each Docker image with --no-cache. Takes ~2-3 minutes.\n' +
      'Do not trigger a demo run during this.',
    successFmt: (body) => {
      const imgs = (body.images_reset || []).length
      const secs = body.duration_s != null ? ` · ${body.duration_s}s` : ''
      return `✅ Images reset — ${imgs} image(s)${secs}`
    },
  })

  const handleResetAppSec = () => runReset({
    label: 'AppSec',
    endpoint: '/admin/env2/reset-appsec',
    confirmMsg:
      'Reset AppSec lab source files to their vulnerable baseline?\n\n' +
      'Covers scanners: semgrep-ec2 (SAST) and trivy-fs-ec2 (SCA).\n' +
      'Restores 7 files under /opt/vuln-labs/appsec-lab/. Takes ~10 seconds.',
    successFmt: (body) => {
      const n = (body.files_restored || []).length
      const secs = body.duration_s != null ? ` · ${body.duration_s}s` : ''
      return `✅ AppSec reset — ${n} file(s)${secs}`
    },
  })

  const handleResetServerless = () => runReset({
    label: 'Serverless',
    endpoint: '/admin/env2/reset-serverless',
    confirmMsg:
      'Reset Serverless lab (lambda_function.py + main.tf) to vulnerable baseline?\n\n' +
      'Covers scanner: serverless-ec2.\n' +
      'Restores /opt/vuln-labs/serverless-lab/{lambda_function.py, main.tf}. Takes ~10 seconds.\n' +
      'Note: file-only reset — deployed AWS state is reconciled by the next fix run\'s terraform apply.',
    successFmt: (body) => {
      const n = (body.files_restored || []).length
      const secs = body.duration_s != null ? ` · ${body.duration_s}s` : ''
      return `✅ Serverless reset — ${n} file(s)${secs}`
    },
  })

  const handleResetPhp = () => runReset({
    label: 'PHP',
    endpoint: '/admin/env2/reset-php',
    confirmMsg:
      'Reset PHP image lab to the vulnerable baseline (brings PHP2Shell CVEs back)?\n\n' +
      'Covers scanner: trivy-image-php-ec2 (CVE-2026-109618 / CVE-2026-109619).\n\n' +
      'Re-fetches Dockerfile from GitHub main + docker build --no-cache. Takes ~3-5 minutes.\n' +
      'Do not trigger a demo run during this.',
    successFmt: (body) => {
      const imgs = (body.images_reset || []).length
      const secs = body.duration_s != null ? ` · ${body.duration_s}s` : ''
      return `✅ PHP reset — ${imgs} image(s)${secs}`
    },
  })

  // Auto-dismiss the reset toast after 8s so it doesn't cover the trace
  useEffect(() => {
    if (!resetToast) return
    const t = setTimeout(() => setResetToast(null), 8000)
    return () => clearTimeout(t)
  }, [resetToast])

  // ----- Derived: agents (master + 4 sub-agents with live status) -----
  // "working" = the agent has emitted at least one trace event for an
  // actively running run. Stays green for the entire duration of the run,
  // not just 30s after the last event (SA-4 can take 60s+ between events
  // during terraform apply).
  const agents = useMemo(() => {
    const activeRunIds = new Set(
      runs.filter((r) => r.status === 'running').map((r) => r.run_id)
    )

    const isActiveInRun = (agentName) => {
      if (activeRunIds.size === 0) return false
      return traceEvents.some(
        (e) => e.from === agentName && activeRunIds.has(e.runId)
      )
    }

    const lastEventFor = (agentName) => {
      const events = traceEvents.filter((e) => e.from === agentName)
      return events[events.length - 1] || null
    }

    const masterEvent = lastEventFor('master')
    const sub1Event = lastEventFor('sub-agent-1')
    const sub2Event = lastEventFor('sub-agent-2')
    const sub3Event = lastEventFor('sub-agent-3')
    const sub4Event = lastEventFor('sub-agent-4')

    return [
      {
        id: 'master',
        name: 'Master Orchestrator',
        role: 'master',
        status: isActiveInRun('master') ? 'working' : 'idle',
        currentTask: masterEvent?.message || null,
      },
      {
        id: 'sub-agent-1',
        name: 'Sub-Agent 1 — Smart Connector',
        role: 'sub',
        status: isActiveInRun('sub-agent-1') ? 'working' : 'idle',
        currentTask: sub1Event?.message || null,
      },
      {
        id: 'sub-agent-2',
        name: 'Sub-Agent 2 — Enrichment Specialist',
        role: 'sub',
        status: isActiveInRun('sub-agent-2') ? 'working' : 'idle',
        currentTask: sub2Event?.message || null,
      },
      {
        id: 'sub-agent-3',
        name: 'Sub-Agent 3 — Remediation Planner',
        role: 'sub',
        status: isActiveInRun('sub-agent-3') ? 'working' : 'idle',
        currentTask: sub3Event?.message || null,
      },
      {
        id: 'sub-agent-4',
        name: 'Sub-Agent 4 — Fixer',
        role: 'sub',
        status: isActiveInRun('sub-agent-4') ? 'working' : 'idle',
        currentTask: sub4Event?.message || null,
      },
    ]
  }, [runs, traceEvents])

  // ----- Derived: live KPI stats for the 4 cards at the top -----
  const stats = useMemo(() => {
    const today = new Date()
    today.setHours(0, 0, 0, 0)

    const activeRuns = runs.filter((r) => r.status === 'running').length
    const queuedRuns = runs.filter((r) => r.status === 'queued').length

    const completedTodayRuns = runs.filter(
      (r) =>
        r.status === 'completed' &&
        r.completed_at &&
        new Date(r.completed_at) >= today
    )

    const avgDurationMs =
      completedTodayRuns.length > 0
        ? completedTodayRuns.reduce(
            (acc, r) =>
              acc + (new Date(r.completed_at) - new Date(r.started_at)),
            0
          ) / completedTodayRuns.length
        : 0

    const avgDuration =
      avgDurationMs > 0
        ? avgDurationMs >= 60000
          ? `${(avgDurationMs / 60000).toFixed(1)}m`
          : `${(avgDurationMs / 1000).toFixed(0)}s`
        : '—'

    const errorEventsToday = traceEvents.filter(
      (e) => e.type === 'error' && new Date(e.timestamp) >= today
    )
    const lastErrorAt =
      errorEventsToday.length > 0
        ? new Date(
            errorEventsToday[errorEventsToday.length - 1].timestamp
          ).toLocaleTimeString()
        : '—'

    return {
      activeAgents: activeRuns > 0 ? 5 : 0,   // 1 master + 4 sub-agents
      activeMasters: activeRuns > 0 ? 1 : 0,
      activeSubs: activeRuns > 0 ? 4 : 0,
      tasksInFlight: activeRuns,
      tasksQueued: queuedRuns,
      completedToday: completedTodayRuns.length,
      avgDuration,
      errorsToday: errorEventsToday.length,
      lastErrorAt,
    }
  }, [runs, traceEvents])

  const agentFilterOptions = useMemo(() => {
    const base = [{ key: 'all', label: 'All agents' }]
    return base.concat(
      agents.map(a => ({ key: a.id, label: a.name }))
    )
  }, [agents])

  const filteredEvents = useMemo(() => {
    // Hide "LLM call — prompt: ... tokens" lines for sub-agents 1/2/3 —
    // they flood the trace with no actionable signal. SA-4 keeps them
    // because its command execution lines are the useful signal.
    const _NOISY_LLM_AGENTS = new Set(['sub-agent-1', 'sub-agent-2', 'sub-agent-3'])
    const _NOISY_LLM_PATTERN = /^LLM call\s*—\s*prompt:/i
    return traceEvents.filter(ev => {
      if (_NOISY_LLM_AGENTS.has(ev.from) && _NOISY_LLM_PATTERN.test(ev.message || '')) {
        return false
      }
      const matchesAgent =
        selectedAgent === 'all' ||
        ev.from === selectedAgent ||
        ev.to === selectedAgent
      const matchesType =
        selectedEventType === 'all' || ev.type === selectedEventType
      const matchesSearch =
        searchTerm === '' ||
        ev.taskId?.toLowerCase().includes(searchTerm.toLowerCase()) ||
        ev.message?.toLowerCase().includes(searchTerm.toLowerCase())
      return matchesAgent && matchesType && matchesSearch
    })
  }, [traceEvents, selectedAgent, selectedEventType, searchTerm])

  const masterAgents = agents.filter(a => a.role === 'master')
  const subAgents = agents.filter(a => a.role === 'sub')

  const formatTime = (iso) => {
    if (!iso) return '—'
    try {
      return new Date(iso).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
      })
    } catch {
      return iso
    }
  }

  const getStatusClass = (status) => {
    if (!status) return 'idle'
    const s = status.toLowerCase()
    if (s === 'working' || s === 'running') return 'working'
    if (s === 'error' || s === 'failed') return 'error'
    if (s === 'done' || s === 'completed') return 'done'
    return 'idle'
  }

  const getEventClass = (type) => {
    if (type === 'dispatch') return 'dispatch'
    if (type === 'result') return 'result'
    if (type === 'error') return 'error'
    return 'message'
  }

  const handleClearTrace = () => {
    // Wire to your backend when ready
  }

  const handleStopActiveRun = async () => {
    const activeRun = runs.find(r => r.status === 'running' || r.status === 'queued')
    if (!activeRun) return

    // Demo runs use a different endpoint (writes to demo.agent_runs) and
    // skip the issue-delete step (demo issues are transient per run).
    if (pipelineMode === 'demo') {
      const ok = window.confirm(
        `Stop the running demo pipeline?\n\n` +
        `This will:\n` +
        `  • Set cancellation_requested on the demo run\n` +
        `  • SA-4 watchdog will abort in-flight fix within seconds\n` +
        `  • Env2 lease releases so the reset buttons unlock\n\n` +
        `Continue?`
      )
      if (!ok) return
      try {
        const res = await fetch(`${API_URL}/agents/demo/runs/${activeRun.run_id}/cancel`, {
          method: 'POST',
        })
        if (!res.ok) {
          alert(`Failed to stop demo run: ${res.status} — ${await res.text()}`)
          return
        }
        const data = await res.json()
        alert(
          `Stopped demo run ${data.run_id.slice(0, 8)}…\n\n` +
          `Previous status: ${data.previous_status}\n` +
          `Active fix_runs flagged: ${data.active_fix_runs_flagged}`
        )
      } catch (err) {
        alert(`Network error stopping demo run: ${err.message || err}`)
      }
      return
    }

    // Real-mode stop — original behavior (cleans issues + resets watermark).
    const scanners = (activeRun.targets?.scanners || []).join(', ') || 'this scanner'
    const ok = window.confirm(
      `Stop the running fetch?\n\n` +
      `This will:\n` +
      `  • Halt the fetch immediately\n` +
      `  • DELETE all issues and raw_findings for ${scanners}\n` +
      `  • Reset the watermark so the next fetch starts fresh\n\n` +
      `Continue?`
    )
    if (!ok) return

    try {
      const res = await fetch(`${API_URL}/agents/runs/${activeRun.run_id}/cancel`, {
        method: 'POST',
      })
      if (!res.ok) {
        const txt = await res.text()
        alert(`Failed to stop run: ${res.status} — ${txt}`)
        return
      }
      const data = await res.json()
      alert(
        `Stopped run ${data.run_id}\n\n` +
        `Scanners cleaned: ${data.scanners_cleaned.join(', ')}\n` +
        `Issues deleted: ${data.issues_deleted}\n` +
        `Raw findings deleted: ${data.raw_findings_deleted}`
      )
    } catch (err) {
      alert(`Network error stopping run: ${err.message || err}`)
    }
  }

  const handleForceReleaseEnv2 = async () => {
    const ok = window.confirm(
      `Force-release env2?\n\n` +
      `This will:\n` +
      `  • Close every active fix_run (marks as failed)\n` +
      `  • Cancel every running agent_run on both schemas\n` +
      `  • Free the env2 lease so you can trigger a fresh reset or pipeline\n\n` +
      `Use this when a run is stuck or you just want to start over.\n\n` +
      `Continue?`
    )
    if (!ok) return
    try {
      const res = await fetch(`${API_URL}/admin/env2/force-release`, { method: 'POST' })
      if (!res.ok) {
        alert(`Force-release failed: ${res.status} — ${await res.text()}`)
        return
      }
      const data = await res.json()
      alert(
        `✅ env2 released\n\n` +
        `Fix runs closed: ${data.fix_runs_closed}\n` +
        `Agent runs closed: ${data.agent_runs_closed}\n` +
        `Schemas touched: ${data.schemas_touched.join(', ') || 'none'}`
      )
      // Immediately re-poll so the reset buttons re-enable without waiting
      // for the next 10s tick.
      try {
        const s = await fetch(`${API_URL}/admin/env2/status`)
        if (s.ok) setEnv2Busy(await s.json())
      } catch { /* transient */ }
    } catch (err) {
      alert(`Network error: ${err.message || err}`)
    }
  }

  return (
    <div className="agents-page-wrapper">
      <Topbar />
      <div className="agents-layout">
        <Sidebar />
        <main className="agents-main">
          <div className="agents-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div>
              <h1>Agents</h1>
              <p className="agents-subtitle">
                Live trace of master agent and sub-agent communication
                {pipelineMode === 'demo' && ' — DEMO PIPELINE (5 pre-seeded issues)'}
              </p>
            </div>
            <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
              {[
                { label: 'CSPM', onClick: handleResetCSPM, title: 'Destroy + recreate CSPM lab (checkov-ec2) — ~60s' },
                { label: 'Images', onClick: handleResetImages, title: 'Rebuild all 3 image labs (infra + java + python) — ~2-3 min' },
                { label: 'AppSec', onClick: handleResetAppSec, title: 'Restore appsec-lab files (semgrep + trivy-fs) — ~10s' },
                { label: 'Serverless', onClick: handleResetServerless, title: 'Restore serverless-lab files (lambda + main.tf) — ~10s' },
                { label: 'PHP', onClick: handleResetPhp, title: 'Rebuild PHP image lab (trivy-image-php-ec2) — ~3-5 min' },
              ].map(({ label, onClick, title }) => {
                const isMe = resettingLabel === label
                const busyBlocked = Boolean(env2Busy?.busy) && !isMe
                const effectiveTitle = busyBlocked
                  ? `env2 busy — ${env2Busy.reason}. Cancel the active run first.`
                  : title
                const disabled = resetting || busyBlocked
                return (
                  <button
                    key={label}
                    type="button"
                    onClick={onClick}
                    disabled={disabled}
                    title={effectiveTitle}
                    style={{
                      padding: '6px 14px',
                      borderRadius: 999,
                      border: '1px solid ' + (disabled && !isMe ? '#334155' : '#f59e0b'),
                      background: disabled && !isMe ? 'transparent' : 'rgba(245,158,11,0.12)',
                      color: disabled && !isMe ? '#64748b' : '#f59e0b',
                      opacity: disabled && !isMe ? 0.55 : 1,
                      fontSize: 12, fontWeight: 600,
                      cursor: resetting ? 'wait' : (busyBlocked ? 'not-allowed' : 'pointer'),
                      display: 'inline-flex', alignItems: 'center', gap: 6,
                    }}
                  >
                    {isMe ? (
                      <>
                        <span style={{
                          width: 10, height: 10, border: '2px solid currentColor',
                          borderTopColor: 'transparent', borderRadius: '50%',
                          animation: 'spin 0.8s linear infinite', display: 'inline-block',
                        }} />
                        Resetting {label}…
                      </>
                    ) : (
                      <>🧹 Reset {label}</>
                    )}
                  </button>
                )
              })}
              {env2Busy?.busy && (
                <button
                  type="button"
                  onClick={handleForceReleaseEnv2}
                  title={`Force-close all active fix_runs + running agent_runs so env2 unlocks immediately. ${env2Busy.reason}`}
                  style={{
                    padding: '6px 14px',
                    borderRadius: 999,
                    border: '1px solid #ef4444',
                    background: 'rgba(239,68,68,0.12)',
                    color: '#ef4444',
                    fontSize: 12, fontWeight: 600, cursor: 'pointer',
                    display: 'inline-flex', alignItems: 'center', gap: 6,
                  }}
                >
                  🚨 Force Release env2
                </button>
              )}
              <button
                type="button"
                onClick={() => setModeManual('real')}
                style={{
                  padding: '6px 14px',
                  borderRadius: 999,
                  border: '1px solid ' + (pipelineMode === 'real' ? '#22c55e' : '#334155'),
                  background: pipelineMode === 'real' ? 'rgba(34,197,94,0.15)' : 'transparent',
                  color: pipelineMode === 'real' ? '#22c55e' : '#94a3b8',
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
                  border: '1px solid ' + (pipelineMode === 'demo' ? '#3b82f6' : '#334155'),
                  background: pipelineMode === 'demo' ? 'rgba(59,130,246,0.15)' : 'transparent',
                  color: pipelineMode === 'demo' ? '#3b82f6' : '#94a3b8',
                  fontSize: 12, fontWeight: 600, cursor: 'pointer',
                }}
              >
                Demo Pipeline
              </button>
            </div>
          </div>

          {resetToast && (
            <div
              role="status"
              style={{
                marginTop: 8,
                padding: '8px 14px',
                borderRadius: 8,
                fontSize: 13,
                border: '1px solid ' + (resetToast.kind === 'success' ? '#22c55e' : '#ef4444'),
                background: resetToast.kind === 'success' ? 'rgba(34,197,94,0.08)' : 'rgba(239,68,68,0.08)',
                color: resetToast.kind === 'success' ? '#22c55e' : '#ef4444',
              }}
            >
              {resetToast.message}
            </div>
          )}

          <style>{`@keyframes spin { to { transform: rotate(360deg); } }`}</style>

          <div className="agents-stats-row">
            <div className="agent-stat-card">
              <div className="agent-stat-value">{stats.activeAgents ?? '—'}</div>
              <div className="agent-stat-label">Active Agents</div>
              <div className="agent-stat-sub">
                Master: {stats.activeMasters ?? '—'} &nbsp;|&nbsp; Sub: {stats.activeSubs ?? '—'}
              </div>
            </div>
            <div className="agent-stat-card">
              <div className="agent-stat-value">{stats.tasksInFlight ?? '—'}</div>
              <div className="agent-stat-label">Tasks In Flight</div>
              <div className="agent-stat-sub">
                Queued: {stats.tasksQueued ?? '—'}
              </div>
            </div>
            <div className="agent-stat-card">
              <div className="agent-stat-value">{stats.completedToday ?? '—'}</div>
              <div className="agent-stat-label">Completed (today)</div>
              <div className="agent-stat-sub">
                Avg duration: {stats.avgDuration ?? '—'}
              </div>
            </div>
          
          </div>

          <div className="agents-content-grid">
            <aside className="agents-side-card">
              <div className="agents-card-header">
                <div className="agents-card-header-left">
                  <h2>Agents</h2>
                  <button
                    className="amc-trigger amc-trigger-icon"
                    onClick={() => setModelConfigOpen(true)}
                    title="Configure which LLM each agent uses"
                    aria-label="Configure agent models"
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <circle cx="12" cy="12" r="3"></circle>
                      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"></path>
                    </svg>
                  </button>
                </div>
                <div className="agents-role-tabs">
                  {ROLE_OPTIONS.map(opt => (
                    <button
                      key={opt.key}
                      className={`role-tab ${
                        selectedAgent === 'all' && opt.key === 'all'
                          ? 'active'
                          : ''
                      }`}
                      onClick={() => setSelectedAgent('all')}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              <div className="agents-list">
                <div className="agents-group-label">Master</div>
                {masterAgents.length === 0 ? (
                  <div className="agents-empty-row">No master agent registered</div>
                ) : (
                  masterAgents.map(agent => (
                    <button
                      key={agent.id}
                      className={`agent-row ${
                        selectedAgent === agent.id ? 'selected' : ''
                      }`}
                      onClick={() => setSelectedAgent(agent.id)}
                    >
                      <span className={`agent-status-dot ${getStatusClass(agent.status)}`}></span>
                      <div className="agent-row-body">
                        <div className="agent-row-name">{agent.name}</div>
                        <div className="agent-row-task">
                          {agent.currentTask || 'Idle'}
                        </div>
                      </div>
                      <span className="agent-role-badge master">M</span>
                    </button>
                  ))
                )}

                <div className="agents-group-label">Sub-agents</div>
                {subAgents.length === 0 ? (
                  <div className="agents-empty-row">No sub-agents registered</div>
                ) : (
                  subAgents.map(agent => (
                    <button
                      key={agent.id}
                      className={`agent-row ${
                        selectedAgent === agent.id ? 'selected' : ''
                      }`}
                      onClick={() => setSelectedAgent(agent.id)}
                    >
                      <span className={`agent-status-dot ${getStatusClass(agent.status)}`}></span>
                      <div className="agent-row-body">
                        <div className="agent-row-name">{agent.name}</div>
                        <div className="agent-row-task">
                          {agent.currentTask || 'Idle'}
                        </div>
                      </div>
                      <span className="agent-role-badge sub">S</span>
                    </button>
                  ))
                )}
              </div>
            </aside>

            <section className="agents-trace-card">
              <div className="agents-card-header">
                <h2>Communication Trace</h2>
                <div className="trace-toolbar">
                  <div className="trace-search">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="11" cy="11" r="8"></circle>
                      <path d="m21 21-4.35-4.35"></path>
                    </svg>
                    <input
                      type="text"
                      placeholder="Search by task ID or message..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                    />
                  </div>

                  <select
                    className="trace-select"
                    value={selectedAgent}
                    onChange={(e) => setSelectedAgent(e.target.value)}
                  >
                    {agentFilterOptions.map(opt => (
                      <option key={opt.key} value={opt.key}>
                        {opt.label}
                      </option>
                    ))}
                  </select>

                  <select
                    className="trace-select"
                    value={selectedEventType}
                    onChange={(e) => setSelectedEventType(e.target.value)}
                  >
                    {EVENT_OPTIONS.map(opt => (
                      <option key={opt.key} value={opt.key}>
                        {opt.label}
                      </option>
                    ))}
                  </select>

                  <label className="trace-toggle">
                    <input
                      type="checkbox"
                      checked={autoScroll}
                      onChange={(e) => setAutoScroll(e.target.checked)}
                    />
                    <span>Auto-scroll</span>
                  </label>

                  <button className="trace-btn" onClick={handleClearTrace} title="Clear trace">
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <polyline points="3 6 5 6 21 6"></polyline>
                      <path d="M19 6l-2 14a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2L5 6"></path>
                    </svg>
                  </button>
                  {runs.some(r => r.status === 'running' || r.status === 'queued') && (
                    <button
                      className="trace-btn trace-btn-stop"
                      onClick={handleStopActiveRun}
                      title={pipelineMode === 'demo'
                        ? 'Cancel the running demo pipeline — SA-4 watchdog aborts in-flight fix; env2 lease releases'
                        : 'Stop the running fetch and wipe its scanner\'s data'}
                    >
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="currentColor">
                        <rect x="6" y="6" width="12" height="12" rx="1"></rect>
                      </svg>
                      <span style={{ marginLeft: 6, fontSize: 12 }}>Stop</span>
                    </button>
                  )}
                </div>
              </div>

              <div className="trace-stream">
                {filteredEvents.length === 0 ? (
                  <div className="trace-empty">
                    <div className="trace-empty-title">Waiting for agent activity</div>
                    <div className="trace-empty-sub">
                      Once the master agent dispatches a task, every message and
                      result will stream in here.
                    </div>
                  </div>
                ) : (
                  filteredEvents.map(ev => (
                    <div
                      key={ev.id}
                      className={`trace-event ${getEventClass(ev.type)} ${
                        selectedTrace?.id === ev.id ? 'selected' : ''
                      }`}
                      onClick={() => setSelectedTrace(ev)}
                    >
                      <div className="trace-event-time">{formatTime(ev.timestamp)}</div>
                      <div className={`trace-event-arrow ${getEventClass(ev.type)}`}>
                        <span className="arrow-from">{ev.fromName || ev.from || '—'}</span>
                        <span className="arrow-symbol">→</span>
                        <span className="arrow-to">{ev.toName || ev.to || '—'}</span>
                      </div>
                      <div className="trace-event-body">
                        <span className={`trace-type-badge ${getEventClass(ev.type)}`}>
                          {ev.type || 'message'}
                        </span>
                        {ev.taskId && (
                          <span className="trace-task-id">{ev.taskId}</span>
                        )}
                        <span className="trace-message">{ev.message}</span>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </section>
          </div>

          {selectedTrace && (
            <div className="trace-detail-overlay" onClick={() => setSelectedTrace(null)}>
              <div className="trace-detail-drawer" onClick={(e) => e.stopPropagation()}>
                <div className="trace-detail-header">
                  <h3>Trace Detail</h3>
                  <button
                    className="trace-detail-close"
                    onClick={() => setSelectedTrace(null)}
                  >
                    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <line x1="18" y1="6" x2="6" y2="18"></line>
                      <line x1="6" y1="6" x2="18" y2="18"></line>
                    </svg>
                  </button>
                </div>
                <dl className="trace-detail-grid">
                  <dt>Task ID</dt>
                  <dd>{selectedTrace.taskId || '—'}</dd>
                  <dt>Type</dt>
                  <dd>{selectedTrace.type || '—'}</dd>
                  <dt>From</dt>
                  <dd>{selectedTrace.fromName || selectedTrace.from || '—'}</dd>
                  <dt>To</dt>
                  <dd>{selectedTrace.toName || selectedTrace.to || '—'}</dd>
                  <dt>Timestamp</dt>
                  <dd>{selectedTrace.timestamp || '—'}</dd>
                  <dt>Duration</dt>
                  <dd>{selectedTrace.durationMs != null ? `${selectedTrace.durationMs} ms` : '—'}</dd>
                </dl>
                <div className="trace-detail-section">
                  <div className="trace-detail-section-label">Message</div>
                  <pre className="trace-detail-payload">
                    {selectedTrace.message || '—'}
                  </pre>
                </div>
                {selectedTrace.payload?.missed_cves?.length > 0 && (
                  <div className="trace-detail-section">
                    <div className="trace-detail-section-label">
                      Cache-missed CVEs ({selectedTrace.payload.missed_cve_count ?? selectedTrace.payload.missed_cves.length}) — went to NVD API
                    </div>
                    <ul className="trace-detail-cve-list">
                      {selectedTrace.payload.missed_cves.map((cve) => (
                        <li key={cve}>
                          <a
                            href={`https://nvd.nist.gov/vuln/detail/${cve}`}
                            target="_blank"
                            rel="noopener noreferrer"
                          >
                            {cve}
                          </a>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="trace-detail-section">
                  <div className="trace-detail-section-label">Payload</div>
                  <pre className="trace-detail-payload">
                    {selectedTrace.payload
                      ? JSON.stringify(selectedTrace.payload, null, 2)
                      : '—'}
                  </pre>
                </div>
              </div>
            </div>
          )}
        </main>
      </div>
      <AgentModelConfig open={modelConfigOpen} onClose={() => setModelConfigOpen(false)} />
    </div>
  )
}
