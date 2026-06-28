export default function SeverityBadge({ severity }) {
  const s = (severity || 'unknown').toLowerCase()
  const classes = {
    critical: 'badge badge-critical',
    high: 'badge badge-high',
    medium: 'badge badge-medium',
    low: 'badge badge-low',
    safe: 'badge badge-safe',
    info: 'badge badge-info',
    clean: 'badge badge-safe',
    suspicious: 'badge badge-high',
    malicious: 'badge badge-critical',
  }
  return <span className={classes[s] || 'badge badge-info'}>{severity || 'Unknown'}</span>
}
