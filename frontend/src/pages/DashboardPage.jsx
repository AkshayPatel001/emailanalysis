import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, Search, AlertTriangle, CheckCircle, XCircle, FileText, Upload, TrendingUp } from 'lucide-react'
import { getCases } from '../api/client'
import SeverityBadge from '../components/Common/SeverityBadge'

export default function DashboardPage() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const navigate = useNavigate()

  useEffect(() => {
    loadCases()
  }, [])

  const loadCases = async () => {
    try {
      const data = await getCases({ limit: 20 })
      setCases(data)
    } catch {
      // API not running — show empty state
    } finally {
      setLoading(false)
    }
  }

  const stats = {
    total: cases.length,
    malicious: cases.filter(c => c.verdict === 'malicious').length,
    suspicious: cases.filter(c => c.verdict === 'suspicious').length,
    clean: cases.filter(c => c.verdict === 'clean').length,
  }

  const statCards = [
    { label: 'Total Analyses', value: stats.total, icon: FileText, color: '#3b82f6', bg: 'from-blue-500/10 to-blue-600/5' },
    { label: 'Malicious', value: stats.malicious, icon: XCircle, color: '#ef4444', bg: 'from-red-500/10 to-red-600/5' },
    { label: 'Suspicious', value: stats.suspicious, icon: AlertTriangle, color: '#f97316', bg: 'from-orange-500/10 to-orange-600/5' },
    { label: 'Clean', value: stats.clean, icon: CheckCircle, color: '#22c55e', bg: 'from-green-500/10 to-green-600/5' },
  ]

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">SOC Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">Email threat analysis overview</p>
        </div>
        <button
          onClick={() => navigate('/analyze')}
          className="btn-primary flex items-center gap-2"
        >
          <Upload className="w-4 h-4" />
          New Analysis
        </button>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 stagger-children">
        {statCards.map(({ label, value, icon: Icon, color, bg }) => (
          <div key={label} className="glass-card p-5">
            <div className="flex items-center justify-between mb-3">
              <div className={`p-2.5 rounded-xl bg-gradient-to-br ${bg} border border-white/5`}>
                <Icon className="w-5 h-5" style={{ color }} />
              </div>
              <TrendingUp className="w-4 h-4 text-gray-600" />
            </div>
            <p className="text-3xl font-bold text-white">{value}</p>
            <p className="text-xs text-gray-500 mt-1 uppercase tracking-wider">{label}</p>
          </div>
        ))}
      </div>

      {/* Quick Analyze CTA */}
      {cases.length === 0 && !loading && (
        <div
          className="glass-card p-12 text-center cursor-pointer animate-pulse-glow"
          onClick={() => navigate('/analyze')}
        >
          <Shield className="w-16 h-16 mx-auto mb-4 text-cyber-cyan opacity-50" />
          <h2 className="text-xl font-semibold text-white mb-2">Start Your First Analysis</h2>
          <p className="text-gray-500 text-sm max-w-md mx-auto mb-6">
            Upload a suspicious email file (.eml, .msg) or paste raw headers to begin threat analysis.
          </p>
          <button className="btn-primary">
            <Search className="w-4 h-4 inline mr-2" />
            Analyze Email
          </button>
        </div>
      )}

      {/* Recent Cases Table */}
      {cases.length > 0 && (
        <div className="glass-card-static overflow-hidden">
          <div className="px-6 py-4 border-b border-navy-700/30 flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white">Recent Analyses</h2>
            <button onClick={() => navigate('/cases')} className="text-xs text-cyber-cyan hover:underline">
              View All →
            </button>
          </div>
          <div className="overflow-x-auto">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Case</th>
                  <th>Subject</th>
                  <th>Sender</th>
                  <th>Verdict</th>
                  <th>Severity</th>
                  <th>Score</th>
                  <th>Date</th>
                </tr>
              </thead>
              <tbody>
                {cases.slice(0, 10).map(c => (
                  <tr key={c.id} className="cursor-pointer" onClick={() => navigate(`/analyze?case=${c.id}`)}>
                    <td className="font-mono text-xs text-cyber-cyan">{c.case_number}</td>
                    <td className="max-w-[200px] truncate">{c.email_subject || '—'}</td>
                    <td className="text-xs text-gray-400">{c.email_sender || '—'}</td>
                    <td><SeverityBadge severity={c.verdict} /></td>
                    <td><SeverityBadge severity={c.severity} /></td>
                    <td className="font-mono font-semibold" style={{
                      color: c.risk_score >= 61 ? '#ef4444' : c.risk_score >= 26 ? '#f97316' : '#22c55e'
                    }}>
                      {c.risk_score?.toFixed(0) || '—'}
                    </td>
                    <td className="text-xs text-gray-500">
                      {new Date(c.created_at).toLocaleDateString()}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
