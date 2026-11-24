import { useEffect, useRef, useState } from 'react'

const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

const ACCEPT_EXT = '.json,.jsonl,.ndjson,.csv,.sarif,application/json,text/csv'
const MAX_BYTES = 50 * 1024 * 1024

/* A unified modal that both creates new scanners and edits existing ones.
   Source types:
     - "api":  PATCH/POST with endpoint + headers + method
     - "file": multipart upload to /admin/scanners/{tool}/upload

   Props:
     tool      : catalog entry { id, name, authType }
     existing  : ScannerConfig from /admin/scanners, or null
     onClose   : () => void
     onSaved   : (successMessage: string) => void  // parent renders a toast
*/
export default function ScannerEndpointModal({ tool, existing, onClose, onSaved }) {
  // Source-type tab: 'api' or 'file'. Defaults based on existing connector.
  const [sourceType, setSourceType] = useState(
    existing?.connector_type === 'file_upload' ? 'file' : 'api'
  )

  // --- API fields ---
  const [endpoint, setEndpoint] = useState('')
  const [method, setMethod] = useState('GET')
  const [responsePath, setResponsePath] = useState('')
  const [headers, setHeaders] = useState([{ key: '', value: '' }])

  // --- File fields ---
  const fileInputRef = useRef(null)
  const [pendingFile, setPendingFile] = useState(null) // File object selected by user
  const [dragOver, setDragOver] = useState(false)

  // --- Shared ---
  const [enabled, setEnabled] = useState(true)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)
  // True when the API returned a redacted placeholder for headers (encryption active)
  const [headersRedacted, setHeadersRedacted] = useState(false)
  // Track header keys removed by the user so we can signal deletion to the backend
  const [removedHeaderKeys, setRemovedHeaderKeys] = useState([])

  // --- Advanced fields (top-level columns on connection_registry) ---
  const [protocol, setProtocol] = useState('REST')
  const [authType, setAuthType] = useState('custom')
  const [rateLimitRpm, setRateLimitRpm] = useState('')
  const [timeoutSec, setTimeoutSec] = useState('')
  const [showAdvanced, setShowAdvanced] = useState(false)

  // --- Custom metadata key/value pairs (e.g. vuln_id_filter, max_findings,
  //     target_instance_id). Lives inside the metadata jsonb column. ---
  const [metaPairs, setMetaPairs] = useState([{ key: '', value: '' }])

  useEffect(() => {
    if (!tool) return
    setError(null)
    setPendingFile(null)
    setRemovedHeaderKeys([])

    if (existing) {
      setSourceType(existing.connector_type === 'file_upload' ? 'file' : 'api')
      setEndpoint(existing.endpoint || '')
      const m = existing.metadata || {}
      setMethod((m.http_method || 'GET').toUpperCase())
      setResponsePath(m.response_path || '')

      // With per-key encryption, the API returns headers as a dict with
      // key names visible and values redacted (e.g. {"Authorization": "••••••••"}).
      // We show the key names with empty value fields so the user can:
      //   - See which headers are configured
      //   - Update individual values by typing in the field
      //   - Leave a field empty to keep the existing encrypted value
      const rawHeaders = m.headers
      if (rawHeaders && typeof rawHeaders === 'object' && !Array.isArray(rawHeaders)) {
        const hasRedactedValues = Object.values(rawHeaders).some(
          (v) => typeof v === 'string' && (v.startsWith('••••') || v.startsWith('****'))
        )
        if (hasRedactedValues) {
          // Show key names with empty values — user fills in only what they want to change
          const hdrList = Object.keys(rawHeaders).map((key) => ({ key, value: '' }))
          setHeaders(hdrList.length ? hdrList : [{ key: '', value: '' }])
          setHeadersRedacted(true)
        } else {
          // Plaintext headers (encryption disabled or legacy) — show as-is
          const hdrList = Object.entries(rawHeaders).map(([key, value]) => ({ key, value }))
          setHeaders(hdrList.length ? hdrList : [{ key: '', value: '' }])
          setHeadersRedacted(false)
        }
      } else if (typeof rawHeaders === 'string' && rawHeaders.includes('configured')) {
        // Blob-encrypted fallback (old format) — show empty fields
        setHeaders([{ key: '', value: '' }])
        setHeadersRedacted(true)
      } else {
        setHeaders([{ key: '', value: '' }])
        setHeadersRedacted(false)
      }
      setEnabled(existing.enabled)
      setProtocol(existing.protocol || 'REST')
      setAuthType(existing.auth_type || 'custom')
      setRateLimitRpm(existing.rate_limit_rpm ?? '')
      setTimeoutSec(existing.timeout_sec ?? '')
      // Hydrate metadata key/value pairs — skip reserved keys the other
      // inputs already manage (http_method, headers, response_path).
      const reservedKeys = new Set(['http_method', 'headers', 'response_path'])
      const customPairs = Object.entries(existing.metadata || {})
        .filter(([k, v]) => !reservedKeys.has(k) && typeof v !== 'object')
        .map(([key, value]) => ({ key, value: String(value) }))
      setMetaPairs(customPairs.length ? customPairs : [{ key: '', value: '' }])
    } else {
      setSourceType('api')
      setEndpoint('')
      setMethod('GET')
      setResponsePath('')
      setHeaders([{ key: '', value: '' }])
      setHeadersRedacted(false)
      setEnabled(true)
      setProtocol('REST')
      setAuthType('custom')
      setRateLimitRpm('')
      setTimeoutSec('')
      setMetaPairs([{ key: '', value: '' }])
    }
  }, [tool, existing])

  if (!tool) return null

  // ---------- API helpers ----------
  const updateHeader = (i, field, value) => {
    setHeaders((prev) => prev.map((h, idx) => (idx === i ? { ...h, [field]: value } : h)))
  }
  const addHeader = () => setHeaders((prev) => [...prev, { key: '', value: '' }])
  // Track removed header keys so we can signal deletion to the backend
  const removeHeader = (i) => {
    setHeaders((prev) => {
      const removed = prev[i]
      // If this header had a key name (i.e. it was a previously saved header),
      // track it for deletion signaling
      if (removed.key.trim() && headersRedacted) {
        setRemovedHeaderKeys((keys) => [...keys, removed.key.trim()])
      }
      return prev.length <= 1 ? [{ key: '', value: '' }] : prev.filter((_, idx) => idx !== i)
    })
  }

  const buildApiMetadata = () => {
    const hdrs = {}
    for (const { key, value } of headers) {
      // Only include headers where the user has entered a value.
      // Empty values on existing headers mean "keep the current encrypted value".
      if (key.trim() && value.trim()) {
        hdrs[key.trim()] = value
      }
    }
    // Mark removed headers with null — backend interprets this as "delete this key"
    for (const key of removedHeaderKeys) {
      hdrs[key] = null
    }
    const meta = { http_method: method }
    // Include headers if user entered any values or removed any, or if this is a new scanner
    if (Object.keys(hdrs).length > 0) {
      meta.headers = hdrs
    } else if (!headersRedacted) {
      // New scanner with no headers — explicitly set empty
      meta.headers = hdrs
    }
    // If headersRedacted and no new values entered, omit headers entirely
    // so the PATCH preserves existing encrypted values via the deep merge.
    if (responsePath.trim()) meta.response_path = responsePath.trim()
    // Merge the custom metadata pairs (vuln_id_filter, max_findings,
    // target_instance_id, etc.). Try to parse numeric / boolean strings so
    // backend code that checks `typeof x === 'number'` works correctly.
    for (const { key, value } of metaPairs) {
      const k = key.trim()
      if (!k) continue
      const raw = value.trim()
      if (raw === '') {
        meta[k] = null
      } else if (/^-?\d+$/.test(raw)) {
        meta[k] = parseInt(raw, 10)
      } else if (/^-?\d*\.\d+$/.test(raw)) {
        meta[k] = parseFloat(raw)
      } else if (raw === 'true' || raw === 'false') {
        meta[k] = raw === 'true'
      } else {
        meta[k] = raw
      }
    }
    return meta
  }

  const updateMetaPair = (i, field, value) => {
    setMetaPairs((prev) => prev.map((p, idx) => (idx === i ? { ...p, [field]: value } : p)))
  }
  const addMetaPair = () => setMetaPairs((prev) => [...prev, { key: '', value: '' }])
  const removeMetaPair = (i) =>
    setMetaPairs((prev) => (prev.length <= 1 ? [{ key: '', value: '' }] : prev.filter((_, idx) => idx !== i)))

  // ---------- File helpers ----------
  const onPickFile = (f) => {
    if (!f) return
    if (f.size > MAX_BYTES) {
      setError(`File is larger than ${MAX_BYTES / (1024 * 1024)} MB.`)
      return
    }
    setError(null)
    setPendingFile(f)
  }

  const onDrop = (e) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer?.files?.[0]
    if (f) onPickFile(f)
  }

  // ---------- Save ----------
  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      if (sourceType === 'api') {
        if (!endpoint.trim()) {
          throw new Error('Endpoint URL is required.')
        }
        const metadata = buildApiMetadata()
        // Top-level column overrides the backend accepts alongside metadata.
        const advanced = {
          protocol: protocol || 'REST',
          auth_type: authType || 'custom',
        }
        if (String(rateLimitRpm).trim() !== '') advanced.rate_limit_rpm = Number(rateLimitRpm)
        if (String(timeoutSec).trim() !== '') advanced.timeout_sec = Number(timeoutSec)
        let res
        if (existing && existing.connector_type !== 'file_upload') {
          res = await fetch(`${API_URL}/admin/scanners/${tool.id}`, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ endpoint: endpoint.trim(), enabled, metadata, ...advanced }),
          })
        } else {
          // Either brand-new or switching from file → api: register fresh.
          res = await fetch(`${API_URL}/admin/scanners`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              tool: tool.id,
              endpoint: endpoint.trim(),
              connector_type: 'user_endpoint',
              metadata,
              enabled,
              ...advanced,
            }),
          })
          if (res.status === 409) {
            // Already exists (was a file_upload), PATCH instead.
            res = await fetch(`${API_URL}/admin/scanners/${tool.id}`, {
              method: 'PATCH',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                endpoint: endpoint.trim(),
                enabled,
                metadata: { ...metadata, connector_type: 'user_endpoint' },
              }),
            })
          }
        }
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.detail || `HTTP ${res.status}`)
        }
        onSaved?.(
          existing
            ? `${tool.name} endpoint updated.`
            : `${tool.name} registered — added to Run a scan.`
        )
        onClose?.()
      } else {
        // file upload
        if (!pendingFile) {
          throw new Error('Pick a file first.')
        }
        const form = new FormData()
        form.append('file', pendingFile)
        const res = await fetch(`${API_URL}/admin/scanners/${tool.id}/upload`, {
          method: 'POST',
          body: form,
        })
        if (!res.ok) {
          const body = await res.json().catch(() => ({}))
          throw new Error(body.detail || `HTTP ${res.status}`)
        }
        onSaved?.(`${tool.name}: uploaded ${pendingFile.name}.`)
        onClose?.()
      }
    } catch (e) {
      setError(`Save failed: ${e.message}`)
    } finally {
      setSaving(false)
    }
  }

  // ---------- Render ----------
  const isFile = sourceType === 'file'
  const currentFilename = existing?.metadata?.file_filename
  const currentFormat = existing?.metadata?.file_format

  return (
    <div className="integration-modal-overlay" onClick={onClose}>
      <div className="integration-modal" onClick={(e) => e.stopPropagation()} style={{ width: 560 }}>
        <h2>{tool.name}</h2>
        <p>
          {existing
            ? `Update the connector configuration for this tool.`
            : `Connect ${tool.name} — paste an API endpoint or upload a scanner export.`}
        </p>

        {/* Source-type toggle */}
        <div className="sem-source-tabs">
          <button
            type="button"
            className={`sem-source-tab ${!isFile ? 'active' : ''}`}
            onClick={() => setSourceType('api')}
          >
            API endpoint
          </button>
          <button
            type="button"
            className={`sem-source-tab ${isFile ? 'active' : ''}`}
            onClick={() => setSourceType('file')}
          >
            File upload
          </button>
        </div>

        {error && (
          <div className="amc-banner amc-banner-err" style={{ marginBottom: 12 }}>
            {error}
          </div>
        )}

        <div className="integration-form">
          {!isFile ? (
            <>
              <label className="sem-label">Endpoint URL</label>
              <span className="sem-help">
                The full URL we’ll call to fetch findings. Check the tool’s API docs — usually a
                “list findings” or “export vulnerabilities” endpoint.
              </span>
              <input
                type="text"
                placeholder="https://api.example.com/v1/findings"
                value={endpoint}
                onChange={(e) => setEndpoint(e.target.value)}
              />

              <label className="sem-label">HTTP method</label>
              <span className="sem-help">
                Usually <strong>GET</strong>. Pick <strong>POST</strong> only if the tool’s docs
                say so.
              </span>
              <div className="sem-method-row">
                {['GET', 'POST'].map((m) => (
                  <button
                    key={m}
                    type="button"
                    className={`sem-method-btn ${method === m ? 'active' : ''}`}
                    onClick={() => setMethod(m)}
                  >
                    {m}
                  </button>
                ))}
              </div>

              <label className="sem-label">Headers (e.g. Authorization)</label>
              <span className="sem-help">
                Auth header the tool needs. Most APIs use{' '}
                <code>Authorization: Bearer &lt;token&gt;</code> or{' '}
                <code>X-API-Key: &lt;key&gt;</code>. Leave empty for public APIs.
              </span>
              {headersRedacted && (
                <div style={{
                  marginBottom: 8,
                  fontSize: 13,
                  padding: '8px 12px',
                  borderRadius: 6,
                  background: 'rgba(56, 189, 248, 0.1)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  color: '#7dd3fc',
                }}>
                  🔒 Values are encrypted. Enter a new value to update a specific header,
                  or leave blank to keep the current encrypted value.
                </div>
              )}
              <div className="sem-headers">
                {headers.map((h, i) => (
                  <div key={i} className="sem-header-row">
                    <input
                      type="text"
                      placeholder="Authorization"
                      value={h.key}
                      onChange={(e) => updateHeader(i, 'key', e.target.value)}
                    />
                    <input
                      type="text"
                      placeholder={headersRedacted && h.key && !h.value ? '••••••••' : 'Bearer eyJhbGciOi…'}
                      value={h.value}
                      onChange={(e) => updateHeader(i, 'value', e.target.value)}
                    />
                    <button
                      type="button"
                      className="sem-header-remove"
                      onClick={() => removeHeader(i)}
                      aria-label="Remove header"
                    >
                      ×
                    </button>
                  </div>
                ))}
                <button type="button" className="sem-add-header" onClick={addHeader}>
                  + Add header
                </button>
              </div>

              <label className="sem-label">Response path (optional)</label>
              <span className="sem-help">
                Where the findings array lives inside the response. Auto-detects common keys
                (<code>findings</code>, <code>vulnerabilities</code>, …); the LLM infers nested
                paths automatically on first scan.
              </span>
              <input
                type="text"
                placeholder="e.g. data.findings"
                value={responsePath}
                onChange={(e) => setResponsePath(e.target.value)}
              />
            </>
          ) : (
            <>
              <label className="sem-label">Scanner export file</label>
              <span className="sem-help">
                Drop a <strong>JSON</strong>, <strong>JSONL</strong>, <strong>CSV</strong>, or{' '}
                <strong>SARIF</strong> file. Up to 50&nbsp;MB. Format is auto-detected from the
                extension and content.
              </span>

              <div
                className={`sem-dropzone ${dragOver ? 'over' : ''}`}
                onDragOver={(e) => {
                  e.preventDefault()
                  setDragOver(true)
                }}
                onDragLeave={() => setDragOver(false)}
                onDrop={onDrop}
                onClick={() => fileInputRef.current?.click()}
              >
                <input
                  ref={fileInputRef}
                  type="file"
                  accept={ACCEPT_EXT}
                  style={{ display: 'none' }}
                  onChange={(e) => onPickFile(e.target.files?.[0])}
                />
                {pendingFile ? (
                  <>
                    <div className="sem-dropzone-filename">{pendingFile.name}</div>
                    <div className="sem-dropzone-meta">
                      {(pendingFile.size / 1024).toFixed(1)} KB · click or drop to replace
                    </div>
                  </>
                ) : currentFilename ? (
                  <>
                    <div className="sem-dropzone-filename">Currently: {currentFilename}</div>
                    <div className="sem-dropzone-meta">
                      format: {currentFormat || 'unknown'} · click or drop to replace
                    </div>
                  </>
                ) : (
                  <>
                    <div className="sem-dropzone-icon">⬆</div>
                    <div className="sem-dropzone-hint">Click to select, or drop file here</div>
                    <div className="sem-dropzone-meta">.json · .jsonl · .csv · .sarif</div>
                  </>
                )}
              </div>
            </>
          )}

          {!isFile && (
            <>
              <button
                type="button"
                className="sem-add-header"
                onClick={() => setShowAdvanced(v => !v)}
                style={{ marginTop: 8 }}
              >
                {showAdvanced ? '− Hide advanced' : '+ Advanced (protocol, auth type, rate limit, metadata…)'}
              </button>

              {showAdvanced && (
                <div style={{ paddingTop: 8, borderTop: '1px solid #1E293B', marginTop: 8 }}>
                  <label className="sem-label">Protocol</label>
                  <span className="sem-help">Transport the connector should use. Most are REST.</span>
                  <div className="sem-method-row">
                    {['REST', 'GRAPHQL', 'S3', 'SSM', 'GIT', 'FILE'].map((p) => (
                      <button
                        key={p}
                        type="button"
                        className={`sem-method-btn ${protocol === p ? 'active' : ''}`}
                        onClick={() => setProtocol(p)}
                      >
                        {p}
                      </button>
                    ))}
                  </div>

                  <label className="sem-label">Auth type</label>
                  <span className="sem-help">How the scanner's API authenticates. Pick <code>custom</code> if you just use Headers above.</span>
                  <select
                    value={authType}
                    onChange={(e) => setAuthType(e.target.value)}
                    style={{ width: '100%', padding: 8, background: '#0F172A', border: '1px solid #334155', borderRadius: 6, color: '#F1F5F9' }}
                  >
                    {['none', 'api_key', 'bearer', 'basic', 'oauth', 'custom'].map((a) => (
                      <option key={a} value={a}>{a}</option>
                    ))}
                  </select>

                  <label className="sem-label">Rate limit (requests/min)</label>
                  <span className="sem-help">Max fetches per minute. Leave empty for no limit.</span>
                  <input
                    type="number"
                    min="0"
                    max="100000"
                    placeholder="e.g. 60"
                    value={rateLimitRpm}
                    onChange={(e) => setRateLimitRpm(e.target.value)}
                  />

                  <label className="sem-label">Timeout (seconds)</label>
                  <span className="sem-help">Per-request timeout. Leave empty for the default (~30s).</span>
                  <input
                    type="number"
                    min="1"
                    max="600"
                    placeholder="e.g. 30"
                    value={timeoutSec}
                    onChange={(e) => setTimeoutSec(e.target.value)}
                  />

                  <label className="sem-label">Custom metadata</label>
                  <span className="sem-help">
                    Extra key/value pairs the connector can read (e.g. <code>vuln_id_filter</code>,
                    <code> max_findings</code>, <code>target_instance_id</code>). Numbers and
                    <code> true</code>/<code>false</code> are parsed automatically.
                  </span>
                  <div className="sem-headers">
                    {metaPairs.map((p, i) => (
                      <div key={i} className="sem-header-row">
                        <input
                          type="text"
                          placeholder="key (e.g. max_findings)"
                          value={p.key}
                          onChange={(e) => updateMetaPair(i, 'key', e.target.value)}
                        />
                        <input
                          type="text"
                          placeholder="value"
                          value={p.value}
                          onChange={(e) => updateMetaPair(i, 'value', e.target.value)}
                        />
                        <button
                          type="button"
                          className="sem-header-remove"
                          onClick={() => removeMetaPair(i)}
                          aria-label="Remove metadata pair"
                        >
                          ×
                        </button>
                      </div>
                    ))}
                    <button type="button" className="sem-add-header" onClick={addMetaPair}>
                      + Add metadata key
                    </button>
                  </div>
                </div>
              )}
            </>
          )}

          <label className="sem-checkbox-row">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            <span>Enabled (show in “Run a scan”)</span>
          </label>
        </div>

        <div className="integration-modal-actions">
          <button className="integration-close-btn" onClick={onClose} disabled={saving}>
            Cancel
          </button>
          <button
            className="scanner-runner-btn"
            onClick={handleSave}
            disabled={saving}
            style={{ minWidth: 120 }}
          >
            {saving
              ? isFile
                ? 'Uploading…'
                : 'Saving…'
              : existing
                ? 'Update'
                : isFile
                  ? 'Upload'
                  : 'Register'}
          </button>
        </div>
      </div>
    </div>
  )
}
