const optionalFalseOrZero = new Set([
  'client',
  'revoked',
  'exclude_container_ips',
  'hole_punch_extension',
  'metric',
  'failure_detection_ms',
  'preferred_candidate',
  'expires_at',
])

const optionalEmptyLists = new Set([
  'advertised_subnets',
  'groups',
  'group_links',
  'overrides',
  'stun_servers',
])

export function normalizeConfig(value: unknown, parentKey = ''): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => normalizeConfig(item, parentKey))
  }
  if (value !== null && typeof value === 'object') {
    const record = value as Record<string, unknown>
    const out: Record<string, unknown> = {}
    for (const key of Object.keys(record).sort()) {
      if (key === 'last_index') continue
      if (key === 'index' && parentKey === 'nodes') continue
      if (key === 'id' && parentKey === 'manual_endpoints') continue
      const v = record[key]
      if (v === undefined || v === null) continue
      if ((v === false || v === '' || v === 0) && optionalFalseOrZero.has(key)) continue
      if (key === 'equal_cost_paths' && v === 'lowest-id') continue
      if (Array.isArray(v) && v.length === 0 && optionalEmptyLists.has(key)) continue
      out[key] = normalizeConfig(v, key)
    }
    return out
  }
  return value
}

export const equal = (a: unknown, b: unknown): boolean =>
  JSON.stringify(normalizeConfig(a)) === JSON.stringify(normalizeConfig(b))
