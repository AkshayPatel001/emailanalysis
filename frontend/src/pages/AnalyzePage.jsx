import { useState, useCallback, useEffect } from 'react'
import { useDropzone } from 'react-dropzone'
import { useSearchParams } from 'react-router-dom'
import { Upload, FileText, Code, Shield, AlertTriangle, Link2, Paperclip, Database, Target, ClipboardList, ChevronRight } from 'lucide-react'
import { analyzeUpload, analyzeHeaders, getAnalysis } from '../api/client'
import RiskGauge from '../components/Common/RiskGauge'
import SeverityBadge from '../components/Common/SeverityBadge'
import LoadingSpinner from '../components/Common/LoadingSpinner'

const TABS = [
  { id: 'summary', label: 'Summary', icon: FileText },
  { id: 'headers', label: 'Headers', icon: Shield },
  { id: 'phishing', label: 'Phishing', icon: AlertTriangle },
  { id: 'urls', label: 'URLs', icon: Link2 },
  { id: 'attachments', label: 'Attachments', icon: Paperclip },
  { id: 'yara', label: 'YARA Rules', icon: Shield },
  { id: 'iocs', label: 'IOCs', icon: Database },
  { id: 'mitre', label: 'MITRE', icon: Target },
  { id: 'actions', label: 'Actions', icon: ClipboardList },
]

export default function AnalyzePage() {
  const [mode, setMode] = useState('upload') // upload | headers
  const [rawHeaders, setRawHeaders] = useState('')
  const [bodyText, setBodyText] = useState('')
  const [result, setResult] = useState(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [activeTab, setActiveTab] = useState('summary')
  const [searchParams, setSearchParams] = useSearchParams()

  useEffect(() => {
    const caseId = searchParams.get('case')
    if (caseId) {
      loadCase(caseId)
    }
  }, [searchParams])

  const loadCase = async (id) => {
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await getAnalysis(id)
      setResult(data)
      setActiveTab('summary')
    } catch (e) {
      setError('Failed to load analysis history.')
    } finally { setLoading(false) }
  }

  const onDrop = useCallback(async (files) => {
    if (files.length === 0) return
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await analyzeUpload(files[0])
      setResult(data)
      setActiveTab('summary')
    } catch (e) {
      setError(e.response?.data?.detail || 'Analysis failed. Is the backend running?')
    } finally { setLoading(false) }
  }, [])

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop, accept: { 'message/rfc822': ['.eml'], 'application/vnd.ms-outlook': ['.msg'], 'text/plain': ['.txt'] },
    maxFiles: 1, maxSize: 25 * 1024 * 1024,
  })

  const handleHeaderAnalysis = async () => {
    if (!rawHeaders.trim()) return
    setLoading(true); setError(null); setResult(null)
    try {
      const data = await analyzeHeaders(rawHeaders, bodyText || null)
      setResult(data)
      setActiveTab('summary')
    } catch (e) {
      setError(e.response?.data?.detail || 'Analysis failed.')
    } finally { setLoading(false) }
  }

  const resetAnalysis = () => { 
    setResult(null); setError(null); setRawHeaders(''); setBodyText('');
    setSearchParams({}); // Clear the URL param
  }

  if (loading) return <LoadingSpinner text="Running threat analysis engines..." />

  // Show results
  if (result) return (
    <div className="space-y-4 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-white">Analysis Results</h1>
          <p className="text-xs text-gray-500 font-mono mt-1">{result.case_number}</p>
        </div>
        <button onClick={resetAnalysis} className="btn-secondary text-sm">New Analysis</button>
      </div>

      {/* Top Summary Row */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <div className="glass-card p-6 flex items-center justify-center">
          <RiskGauge score={result.risk_score || 0} verdict={result.verdict || 'clean'} size={160} />
        </div>
        <div className="lg:col-span-2 glass-card p-6 space-y-3">
          <h3 className="text-sm font-semibold text-gray-400 uppercase tracking-wider">Email Summary</h3>
          <div className="grid grid-cols-2 gap-3 text-sm">
            {[
              ['Subject', result.email_metadata?.subject],
              ['From', result.email_metadata?.sender],
              ['To', result.email_metadata?.recipient],
              ['Date', result.email_metadata?.date],
              ['Reply-To', result.email_metadata?.reply_to],
              ['Return-Path', result.email_metadata?.return_path],
              ['Message-ID', result.email_metadata?.message_id],
              ['Attachments', result.email_metadata?.attachment_count || 0],
            ].map(([label, value]) => (
              <div key={label}>
                <span className="text-gray-500 text-xs">{label}</span>
                <p className="text-gray-300 text-sm truncate font-mono">{value || '—'}</p>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="glass-card-static overflow-hidden">
        <div className="flex overflow-x-auto border-b border-navy-700/30 px-2">
          {TABS.map(({ id, label, icon: Icon }) => (
            <button key={id} onClick={() => setActiveTab(id)}
              className={`tab-button flex items-center gap-2 ${activeTab === id ? 'active' : ''}`}>
              <Icon className="w-3.5 h-3.5" /> {label}
            </button>
          ))}
        </div>
        <div className="p-5">{renderTabContent(activeTab, result)}</div>
      </div>
    </div>
  )

  // Input form
  return (
    <div className="space-y-6 animate-fade-in">
      <div>
        <h1 className="text-2xl font-bold text-white">Analyze Email</h1>
        <p className="text-sm text-gray-500 mt-1">Upload a suspicious email or paste raw headers</p>
      </div>

      {/* Mode Toggle */}
      <div className="flex gap-2">
        <button onClick={() => setMode('upload')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${mode === 'upload' ? 'bg-cyber-blue/20 text-cyber-cyan border border-cyber-blue/30' : 'text-gray-500 hover:text-gray-300'}`}>
          <Upload className="w-4 h-4 inline mr-2" />File Upload
        </button>
        <button onClick={() => setMode('headers')}
          className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${mode === 'headers' ? 'bg-cyber-blue/20 text-cyber-cyan border border-cyber-blue/30' : 'text-gray-500 hover:text-gray-300'}`}>
          <Code className="w-4 h-4 inline mr-2" />Raw Headers
        </button>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{error}</div>
      )}

      {mode === 'upload' ? (
        <div {...getRootProps()} className={`dropzone p-16 text-center ${isDragActive ? 'dropzone-active' : ''}`}>
          <input {...getInputProps()} />
          <Upload className="w-12 h-12 mx-auto mb-4 text-cyber-blue/50" />
          <p className="text-lg text-gray-300 mb-2">
            {isDragActive ? 'Drop the email file here...' : 'Drag & drop an email file here'}
          </p>
          <p className="text-sm text-gray-500">Supports .eml, .msg, .txt — Max 25MB</p>
        </div>
      ) : (
        <div className="space-y-4">
          <div>
            <label className="text-xs text-gray-400 uppercase tracking-wider mb-2 block">Email Headers *</label>
            <textarea value={rawHeaders} onChange={e => setRawHeaders(e.target.value)}
              placeholder="Paste raw email headers here..."
              className="w-full h-48 bg-navy-900 border border-navy-700/50 rounded-xl p-4 text-sm font-mono text-gray-300 placeholder-gray-600 focus:border-cyber-blue/50 focus:outline-none resize-none" />
          </div>
          <div>
            <label className="text-xs text-gray-400 uppercase tracking-wider mb-2 block">Email Body (optional)</label>
            <textarea value={bodyText} onChange={e => setBodyText(e.target.value)}
              placeholder="Paste email body text..."
              className="w-full h-32 bg-navy-900 border border-navy-700/50 rounded-xl p-4 text-sm text-gray-300 placeholder-gray-600 focus:border-cyber-blue/50 focus:outline-none resize-none" />
          </div>
          <button onClick={handleHeaderAnalysis} disabled={!rawHeaders.trim()} className="btn-primary disabled:opacity-40">
            <Shield className="w-4 h-4 inline mr-2" />Analyze Headers
          </button>
        </div>
      )}
    </div>
  )
}

function renderTabContent(tab, r) {
  switch (tab) {
    case 'summary': return <SummaryTab result={r} />
    case 'headers': return <HeadersTab data={r.header_analysis} />
    case 'phishing': return <PhishingTab data={r.phishing_analysis} />
    case 'urls': return <UrlsTab data={r.url_analysis} />
    case 'attachments': return <AttachmentsTab data={r.attachment_analysis} />
    case 'yara': return <YaraTab data={r.yara_analysis} />
    case 'iocs': return <IOCsTab data={r.ioc_summary} />
    case 'mitre': return <MitreTab data={r.mitre_mappings} />
    case 'actions': return <ActionsTab data={r.recommended_actions} caseId={r.case_id} />
    default: return null
  }
}

function SummaryTab({ result }) {
  const scoring = result.risk_scoring
  if (!scoring) return <p className="text-gray-500">No scoring data.</p>
  return (
    <div className="space-y-4">
      <h3 className="text-sm font-semibold text-gray-400 uppercase">Risk Score Breakdown</h3>
      {scoring.breakdown?.map((b, i) => (
        <div key={i} className="flex items-center gap-4">
          <div className="flex-1">
            <div className="flex justify-between text-xs mb-1">
              <span className="text-gray-300 font-medium">{b.category}</span>
              <span className="text-gray-500">{b.points}/{b.max_points}</span>
            </div>
            <div className="confidence-bar">
              <div className="confidence-bar-fill" style={{
                width: `${b.max_points > 0 ? (b.points / b.max_points) * 100 : 0}%`,
                background: b.points > b.max_points * 0.6 ? '#ef4444' : b.points > b.max_points * 0.3 ? '#f97316' : '#22c55e',
              }} />
            </div>
            <p className="text-[11px] text-gray-600 mt-1">{b.description}</p>
          </div>
        </div>
      ))}
    </div>
  )
}

function HeadersTab({ data }) {
  if (!data) return <p className="text-gray-500">No header data.</p>
  return (
    <div className="space-y-3">
      {/* Auth Results */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 mb-4">
        {['spf', 'dkim', 'dmarc'].map(mech => {
          const auth = data[mech]
          return (
            <div key={mech} className={`p-4 rounded-xl border ${auth?.is_pass ? 'border-green-500/30 bg-green-500/5' : auth ? 'border-red-500/30 bg-red-500/5' : 'border-gray-700/30 bg-gray-800/20'}`}>
              <div className="flex items-center justify-between mb-1">
                <span className="text-xs font-bold uppercase text-gray-400">{mech}</span>
                <SeverityBadge severity={auth?.is_pass ? 'safe' : auth ? 'high' : 'info'} />
              </div>
              <p className="text-sm font-semibold text-white">{auth?.result?.toUpperCase() || 'NOT PRESENT'}</p>
              {auth?.detail && <p className="text-[11px] text-gray-500 mt-1 truncate">{auth.detail}</p>}
            </div>
          )
        })}
      </div>
      {/* Findings */}
      <h4 className="text-xs font-semibold text-gray-400 uppercase">Findings</h4>
      <table className="data-table">
        <thead><tr><th>Severity</th><th>Finding</th><th>Description</th></tr></thead>
        <tbody>
          {data.findings?.map((f, i) => (
            <tr key={i}>
              <td><SeverityBadge severity={f.severity} /></td>
              <td className="font-medium text-white text-sm">{f.title}</td>
              <td className="text-xs">{f.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function PhishingTab({ data }) {
  if (!data || !data.indicators?.length) return <p className="text-gray-500">No phishing indicators detected.</p>
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4">
        <div className={`px-4 py-2 rounded-xl text-sm font-bold ${data.is_likely_phishing ? 'bg-red-500/10 text-red-400 border border-red-500/30' : 'bg-green-500/10 text-green-400 border border-green-500/30'}`}>
          {data.is_likely_phishing ? '⚠ LIKELY PHISHING' : '✓ LOW PHISHING RISK'}
        </div>
        <span className="text-sm text-gray-400">Overall Confidence: <strong className="text-white">{(data.overall_confidence * 100).toFixed(0)}%</strong></span>
      </div>
      {data.indicators.map((ind, i) => (
        <div key={i} className="p-4 rounded-xl bg-navy-800/50 border border-navy-700/30 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <SeverityBadge severity={ind.severity} />
              <span className="text-sm font-medium text-white">{ind.indicator}</span>
            </div>
            <span className="text-xs font-mono text-gray-400">{(ind.confidence * 100).toFixed(0)}%</span>
          </div>
          <p className="text-xs text-gray-500">{ind.explanation}</p>
          <div className="confidence-bar">
            <div className="confidence-bar-fill" style={{
              width: `${ind.confidence * 100}%`,
              background: ind.confidence >= 0.8 ? '#ef4444' : ind.confidence >= 0.6 ? '#f97316' : '#eab308',
            }} />
          </div>
          <p className="text-[11px] font-mono text-gray-600">Evidence: {ind.evidence}</p>
        </div>
      ))}
    </div>
  )
}

function UrlsTab({ data }) {
  if (!data || !data.urls?.length) return <p className="text-gray-500">No URLs found.</p>
  return (
    <div className="space-y-3">
      <div className="flex gap-4 text-sm">
        <span className="text-gray-400">Found: <strong className="text-white">{data.urls_found}</strong></span>
        <span className="text-red-400">Malicious: <strong>{data.malicious_count}</strong></span>
        <span className="text-orange-400">Suspicious: <strong>{data.suspicious_count}</strong></span>
      </div>
      <table className="data-table">
        <thead><tr><th>URL</th><th>Domain</th><th>Risk</th><th>Flags</th></tr></thead>
        <tbody>
          {data.urls.map((u, i) => (
            <tr key={i}>
              <td className="font-mono text-xs max-w-[300px] truncate">{u.url}</td>
              <td className="text-xs">{u.domain}</td>
              <td><SeverityBadge severity={u.risk_level} /></td>
              <td className="text-xs space-x-1">
                {u.is_shortened && <span className="badge badge-medium">shortened</span>}
                {u.is_punycode && <span className="badge badge-high">punycode</span>}
                {u.is_typosquat && <span className="badge badge-critical">typosquat: {u.typosquat_target}</span>}
                {u.suspicious_tld && <span className="badge badge-medium">sus TLD</span>}
                {!u.is_https && <span className="badge badge-low">HTTP</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AttachmentsTab({ data }) {
  if (!data || !data.attachments?.length) return <p className="text-gray-500">No attachments found.</p>
  return (
    <div className="space-y-3">
      {data.attachments.map((a, i) => (
        <div key={i} className={`p-4 rounded-xl border ${a.is_suspicious ? 'border-red-500/30 bg-red-500/5' : 'border-navy-700/30 bg-navy-800/30'}`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Paperclip className="w-4 h-4 text-gray-400" />
              <span className="text-sm font-medium text-white">{a.filename}</span>
            </div>
            <SeverityBadge severity={a.risk_level} />
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
            <div><span className="text-gray-500">Size:</span> <span className="text-gray-300">{a.file_size_human}</span></div>
            <div><span className="text-gray-500">Type:</span> <span className="text-gray-300">{a.mime_type || a.extension}</span></div>
            <div><span className="text-gray-500">MD5:</span> <span className="text-gray-300 font-mono">{a.md5?.slice(0,16)}...</span></div>
            <div><span className="text-gray-500">SHA256:</span> <span className="text-gray-300 font-mono">{a.sha256?.slice(0,16)}...</span></div>
          </div>
          {a.findings?.length > 0 && (
            <div className="mt-2 space-y-1">
              {a.findings.map((f, j) => <p key={j} className="text-xs text-orange-400">• {f}</p>)}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}

function IOCsTab({ data }) {
  if (!data || data.total_count === 0) return <p className="text-gray-500">No IOCs extracted.</p>
  const allIOCs = [...(data.ips||[]), ...(data.domains||[]), ...(data.urls||[]), ...(data.hashes||[]), ...(data.emails||[])]
  return (
    <div>
      <p className="text-sm text-gray-400 mb-3">Total IOCs: <strong className="text-white">{data.total_count}</strong></p>
      <table className="data-table">
        <thead><tr><th>Type</th><th>Value (Defanged)</th><th>Context</th></tr></thead>
        <tbody>
          {allIOCs.slice(0, 50).map((ioc, i) => (
            <tr key={i}>
              <td><span className="badge badge-info">{ioc.ioc_type}</span></td>
              <td className="font-mono text-xs text-cyber-cyan">{ioc.defanged}</td>
              <td className="text-xs text-gray-500">{ioc.context}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function MitreTab({ data }) {
  if (!data?.length) return <p className="text-gray-500">No MITRE ATT&CK techniques mapped.</p>
  return (
    <div className="space-y-3">
      {data.map((m, i) => (
        <div key={i} className="p-4 rounded-xl bg-purple-500/5 border border-purple-500/20">
          <div className="flex items-center justify-between mb-1">
            <div className="flex items-center gap-2">
              <span className="text-xs font-mono font-bold text-purple-400">{m.technique_id}</span>
              <span className="text-sm font-medium text-white">{m.technique_name}</span>
            </div>
            <span className="text-xs text-gray-400">{(m.confidence * 100).toFixed(0)}% confidence</span>
          </div>
          <p className="text-xs text-gray-500">{m.description}</p>
          <div className="flex items-center gap-2 mt-2">
            <span className="badge badge-info">{m.tactic}</span>
            {m.evidence && <span className="text-[11px] text-gray-600">Evidence: {m.evidence}</span>}
          </div>
        </div>
      ))}
    </div>
  )
}

function ActionsTab({ data, caseId }) {
  const [purging, setPurging] = useState(false);
  const [purgeResult, setPurgeResult] = useState(null);

  const handlePurge = async () => {
    if (!window.confirm("WARNING: This will permanently delete emails matching this campaign from all M365 mailboxes. Continue?")) return;
    
    setPurging(true);
    setPurgeResult(null);
    try {
      // In a real scenario, these credentials would be securely fetched from backend settings
      // We pass placeholders for the sake of the demo
      const res = await axios.post(`/api/remediation/${caseId}`, {
        action_type: 'delete'
      });
      setPurgeResult("Remediation task queued successfully. Check logs for details.");
    } catch (e) {
      setPurgeResult("Error queuing remediation task.");
    } finally {
      setPurging(false);
    }
  };

  if (!data?.length) return <p className="text-gray-500">No recommendations.</p>
  return (
    <div className="space-y-2">
      <h3 className="text-sm font-semibold text-gray-400 uppercase">Recommended Response Actions</h3>
      {data.map((action, i) => (
        <div key={i} className="flex items-start gap-3 p-3 rounded-lg bg-navy-800/30 border border-navy-700/20">
          <ChevronRight className="w-4 h-4 text-cyber-cyan mt-0.5 shrink-0" />
          <p className="text-sm text-gray-300">{action}</p>
        </div>
      ))}
      
      <div className="mt-8 p-6 rounded-xl border border-red-500/30 bg-red-500/5">
        <h3 className="text-lg font-bold text-red-400 mb-2">Automated SOAR Remediation</h3>
        <p className="text-sm text-gray-400 mb-4">
          Execute an automated playbook to search all Microsoft 365 mailboxes and permanently purge this malicious email.
        </p>
        <button 
          onClick={handlePurge}
          disabled={purging}
          className="bg-red-600 hover:bg-red-500 text-white font-bold py-2 px-4 rounded-md shadow-lg disabled:opacity-50"
        >
          {purging ? "Queuing Task..." : "Purge Campaign (M365)"}
        </button>
        {purgeResult && (
          <p className="mt-3 text-sm text-gray-300 font-mono bg-navy-900 p-2 rounded border border-navy-700/50">
            {purgeResult}
          </p>
        )}
      </div>
    </div>
  )
}

function YaraTab({ data }) {
  if (!data?.matches?.length) return <p className="text-gray-500">No YARA rule matches detected.</p>
  return (
    <div className="space-y-4">
      <div className="flex items-center gap-4 mb-4">
        <span className="text-sm text-gray-400">Total Matches: <strong className="text-white">{data.total_matches}</strong></span>
      </div>
      {data.matches.map((m, i) => (
        <div key={i} className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Shield className="w-5 h-5 text-red-400" />
              <span className="text-md font-bold text-white font-mono">{m.rule_name}</span>
            </div>
            <span className="badge badge-critical">Rule Hit</span>
          </div>
          {m.meta?.context && <p className="text-xs text-gray-400">Context: <span className="font-mono text-gray-300">{m.meta.context}</span></p>}
          {m.strings_matched?.length > 0 && (
            <div className="mt-2 space-y-1 bg-navy-900 p-2 rounded-md border border-navy-700/50">
              <p className="text-[10px] uppercase text-gray-500 font-bold mb-1">Matched Strings</p>
              {m.strings_matched.map((s, j) => (
                <p key={j} className="text-xs font-mono text-orange-400 break-all">{s}</p>
              ))}
            </div>
          )}
        </div>
      ))}
    </div>
  )
}
