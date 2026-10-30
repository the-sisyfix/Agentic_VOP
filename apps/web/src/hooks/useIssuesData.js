// Issues page data hook — pulls rows from the `issue_with_asset` view (so we
// get the asset join for free) and maps them into the shape the existing
// Issues.jsx UI expects (the 12-column ISSUE_COLUMNS list).
//
// Sort: created_at DESC — newest issues at the top.
// Limit: 500 — covers today's ~404 rows with headroom. Bump to server-side
//        pagination if/when this grows past a few thousand.
// Realtime: subscribe to INSERT/UPDATE on `issues`, debounce 600 ms, re-fetch.

import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

const FETCH_LIMIT = 500

export function useIssuesData() {
  const [issues, setIssues] = useState([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let mounted = true
    let debounceTimer = null

    async function loadAll() {
      const { data, error } = await supabase
        .from('issue_with_asset')
        .select(
          'id, source, cve_id, source_vuln_id, severity, derived_risk, title, description, ' +
            'first_detected, cvss_attack_vector, remediation_suggestion, ' +
            'asset_identity, created_at, ' +
            'asset_id, asset_name, asset_type'
        )
        .order('created_at', { ascending: false })
        .limit(FETCH_LIMIT)

      if (!mounted) return
      if (error) {
        // Surface in console so devs see schema/RLS issues; UI just stays empty.
        console.error('useIssuesData fetch error:', error)
        setLoading(false)
        return
      }

      const mapped = (data || []).map((row) => ({
        // Pad the bigint id to a 5-digit "ISS-NNNNN" so the column has a stable shape.
        issue_id: row.id != null ? `ISS-${String(row.id).padStart(5, '0')}` : '',
        // Asset ID: the actual DB asset_id (numeric or string ID)
        asset_id: row.asset_id || '',
        // Asset name: prefer DB asset_name, fall back to asset_identity display values
        asset_name:
          row.asset_name ||
          row?.asset_identity?.dns ||
          row?.asset_identity?.name ||
          row?.asset_identity?.hostname ||
          '',
        asset_type: row.asset_type || '',
        // CVE for CVE-emitting scanners (trivy, grype); fall back to the
        // scanner's native vuln id for CSPM/SAST (CKV_AWS_24, rule.name, etc.)
        // so the column is never blank. UI column labeled "CVE / ID".
        cve_id: row.cve_id || row.source_vuln_id || '',
        severity: row.severity || '',
        derived_risk: row.derived_risk,
        // Prefer description; fall back to title (Checkov issues often have
        // title but no description).
        description: row.description || row.title || '',
        // Threat vector ≈ CVSS attack vector (closest field we have today).
        threat_vector: row.cvss_attack_vector || '',
        // Derived: do we have an AI-suggested fix for this finding?
        remediable: row.remediation_suggestion ? 'Yes' : 'No',
        source: row.source || '',
        // Fall back to created_at when first_detected is not populated.
        first_detected: row.first_detected || row.created_at || '',
        // No CVE-published-date in our schema today — leave blank for now.
        cve_published: '',
      }))

      setIssues(mapped)
      setLoading(false)
    }

    loadAll()

    const channel = supabase
      .channel('issues-page-stream')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'issues' },
        () => {
          if (debounceTimer) clearTimeout(debounceTimer)
          debounceTimer = setTimeout(() => {
            if (mounted) loadAll()
          }, 600)
        }
      )
      .subscribe()

    return () => {
      mounted = false
      if (debounceTimer) clearTimeout(debounceTimer)
      supabase.removeChannel(channel)
    }
  }, [])

  return { issues, loading }
}
