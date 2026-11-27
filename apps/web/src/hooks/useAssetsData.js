// Assets page data hook — pulls rows from the `assets` table and maps them
// into the shape the existing Assets.jsx UI expects.
//
// Sort: name ASC — alphabetical by default.
// Limit: 500 — covers today's asset count with headroom.
// Realtime: subscribe to INSERT/UPDATE/DELETE on `assets`, debounce 600 ms, re-fetch.

import { useEffect, useState } from 'react'
import { supabase } from '../lib/supabase'

const FETCH_LIMIT = 500

// Map numeric business_criticality (1-5) to display labels.
const CRITICALITY_MAP = {
  5: 'Critical',
  4: 'High',
  3: 'Medium',
  2: 'Low',
  1: 'Info',
}

// Stale-while-revalidate cache — same pattern as useDashboardData /
// useIssuesData. Instant paint on revisits so the Assets page never
// flashes "No assets found" during the 1-3s fetch.
const CACHE_KEY = 'sisyfix:assets:v1'
const CACHE_MAX_AGE_MS = 24 * 60 * 60 * 1000

function loadCache() {
  try {
    const raw = localStorage.getItem(CACHE_KEY)
    if (!raw) return null
    const cached = JSON.parse(raw)
    if (!cached || !cached.ts || Date.now() - cached.ts > CACHE_MAX_AGE_MS) return null
    return cached.assets || null
  } catch {
    return null
  }
}

function saveCache(assets) {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify({ ts: Date.now(), assets }))
  } catch {
    // best-effort
  }
}

export function useAssetsData() {
  const _cached = loadCache()
  const [assets, setAssets] = useState(_cached || [])
  const [loading, setLoading] = useState(!_cached)

  useEffect(() => {
    let mounted = true
    let debounceTimer = null

    async function loadAll() {
      const { data, error } = await supabase
        .from('assets')
        .select(
          'asset_id, name, hostname, ip_address, asset_type, environment, ' +
            'business_owner, contact_email, application_name, description, ' +
            'repo_url, exposure, business_criticality, data_classification, ' +
            'compliance_tags, owner_team, network_zone, aliases, last_seen_at, ' +
            'created_at, updated_at'
        )
        .order('asset_id', { ascending: true })
        .limit(FETCH_LIMIT)

      if (!mounted) return
      if (error) {
        console.error('useAssetsData fetch error:', error)
        setLoading(false)
        return
      }

      const mapped = (data || []).map((row) => ({
        asset_id: row.asset_id || '',
        type: row.asset_type || '',
        // Display name: prefer name, then hostname, then application_name
        hostname: row.name || row.hostname || row.application_name || '',
        application_name: row.application_name || row.hostname || '',
        asset_criticality: CRITICALITY_MAP[row.business_criticality] || 'Low',
        business_criticality: row.business_criticality,
        environment: row.environment
          ? row.environment.charAt(0).toUpperCase() + row.environment.slice(1)
          : '',
        it_owner: row.business_owner || row.owner_team || '',
        contact_email: row.contact_email || '',
        data_classification: row.data_classification
          ? row.data_classification.charAt(0).toUpperCase() + row.data_classification.slice(1)
          : '',
        exposure: row.exposure || '',
        network_zone: row.network_zone || '',
        compliance_tags: row.compliance_tags || [],
        description: row.description || '',
        repo_url: row.repo_url || '',
        ip_address: row.ip_address || '',
        last_seen_at: row.last_seen_at,
        name: row.name || '',
        aliases: row.aliases || [],
      }))

      setAssets(mapped)
      saveCache(mapped)
      setLoading(false)
    }

    loadAll()

    const channel = supabase
      .channel('assets-page-stream')
      .on(
        'postgres_changes',
        { event: '*', schema: 'public', table: 'assets' },
        () => {
          if (debounceTimer) clearTimeout(debounceTimer)
          debounceTimer = setTimeout(() => {
            if (mounted) loadAll()
          }, 600)
        }
      )
      .subscribe()

    // Refetch when tab becomes visible or window gains focus. Throttled to
    // one call per 5s to coalesce rapid focus/blur events.
    let lastRefreshAt = Date.now()
    const MIN_REFRESH_INTERVAL_MS = 5_000
    const maybeRefresh = () => {
      const now = Date.now()
      if (!mounted || document.hidden) return
      if (now - lastRefreshAt < MIN_REFRESH_INTERVAL_MS) return
      lastRefreshAt = now
      loadAll()
    }
    document.addEventListener('visibilitychange', maybeRefresh)
    window.addEventListener('focus', maybeRefresh)

    return () => {
      mounted = false
      if (debounceTimer) clearTimeout(debounceTimer)
      supabase.removeChannel(channel)
      document.removeEventListener('visibilitychange', maybeRefresh)
      window.removeEventListener('focus', maybeRefresh)
    }
  }, [])

  return { assets, loading }
}

/**
 * Fetch issues for a specific asset.
 * 
 * Queries issue_with_asset by asset_id (view-resolved) and also by
 * asset_identity->>project/repo matching this asset's name and aliases,
 * to handle cases where the view's JOIN resolved an issue to a different
 * asset due to stale or overlapping aliases.
 */
export async function fetchIssuesForAsset(asset) {
  const assetId = asset.asset_id
  const assetName = asset.name || ''
  const aliases = asset.aliases || []

  // All identifiers this asset is known by.
  const identifiers = [assetName, ...aliases].filter(Boolean)

  // Build OR conditions for comprehensive matching.
  const orParts = [`asset_id.eq.${assetId}`]
  for (const ident of identifiers) {
    orParts.push(`asset_identity->>project.eq.${ident}`)
    orParts.push(`asset_identity->>repo.eq.${ident}`)
  }

  const { data, error } = await supabase
    .from('issue_with_asset')
    .select(
      'id, source, cve_id, severity, derived_risk, title, description, ' +
        'first_detected, cvss_attack_vector, remediation_suggestion, ' +
        'asset_identity, created_at, asset_id, asset_name, asset_type'
    )
    .or(orParts.join(','))
    .order('derived_risk', { ascending: false, nullsFirst: false })
    .limit(200)

  if (error) {
    console.error('fetchIssuesForAsset error:', error)
    return []
  }

  // Deduplicate by issue id (LEFT JOIN can produce duplicates).
  const seenIds = new Set()
  const rows = []
  for (const row of data || []) {
    if (!seenIds.has(row.id)) {
      seenIds.add(row.id)
      rows.push(row)
    }
  }

  return rows.map((row) => ({
    issue_id: row.id != null ? `ISS-${String(row.id).padStart(5, '0')}` : '',
    asset_name:
      row.asset_name ||
      row?.asset_identity?.hostname ||
      row?.asset_identity?.project ||
      '',
    asset_type: row.asset_type || '',
    cve_id: row.cve_id || '',
    severity: row.severity || '',
    derived_risk: row.derived_risk,
    description: row.description || row.title || '',
    threat_vector: row.cvss_attack_vector || '',
    remediable: row.remediation_suggestion ? 'Yes' : 'No',
    source: row.source || '',
    first_detected: row.first_detected || row.created_at || '',
  }))
}
