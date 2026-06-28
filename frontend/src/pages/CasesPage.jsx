import { useState, useEffect } from 'react'
import { getCases, updateCase, deleteCase } from '../api/client'
import SeverityBadge from '../components/Common/SeverityBadge'
import { FolderOpen, Trash2, Save, X } from 'lucide-react'

export default function CasesPage() {
  const [cases, setCases] = useState([])
  const [loading, setLoading] = useState(true)
  const [editingId, setEditingId] = useState(null)
  const [editNotes, setEditNotes] = useState('')
  const [editStatus, setEditStatus] = useState('')
  const [filter, setFilter] = useState({ status: '', severity: '' })

  useEffect(() => { loadCases() }, [filter])

  const loadCases = async () => {
    try {
      const params = {}
      if (filter.status) params.status = filter.status
      if (filter.severity) params.severity = filter.severity
      const data = await getCases(params)
      setCases(data)
    } catch { /* backend offline */ }
    finally { setLoading(false) }
  }

  const handleEdit = (c) => {
    setEditingId(c.id); setEditNotes(c.analyst_notes || ''); setEditStatus(c.status)
  }

  const handleSave = async (id) => {
    await updateCase(id, { status: editStatus, analyst_notes: editNotes })
    setEditingId(null); loadCases()
  }

  const handleDelete = async (id) => {
    if (confirm('Delete this case and all associated data?')) {
      await deleteCase(id); loadCases()
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Case Management</h1>
          <p className="text-sm text-gray-500 mt-1">{cases.length} cases</p>
        </div>
        <div className="flex gap-2">
          <select value={filter.status} onChange={e => setFilter(f => ({...f, status: e.target.value}))}
            className="bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none">
            <option value="">All Statuses</option>
            {['new','in_progress','completed','escalated','closed'].map(s =>
              <option key={s} value={s}>{s.replace('_',' ')}</option>
            )}
          </select>
          <select value={filter.severity} onChange={e => setFilter(f => ({...f, severity: e.target.value}))}
            className="bg-navy-800 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none">
            <option value="">All Severities</option>
            {['critical','high','medium','low','safe'].map(s =>
              <option key={s} value={s}>{s}</option>
            )}
          </select>
        </div>
      </div>

      {cases.length === 0 && !loading ? (
        <div className="glass-card p-16 text-center">
          <FolderOpen className="w-12 h-12 mx-auto mb-4 text-gray-600" />
          <p className="text-gray-500">No cases found. Run an analysis to create a case.</p>
        </div>
      ) : (
        <div className="glass-card-static overflow-hidden">
          <table className="data-table">
            <thead>
              <tr>
                <th>Case #</th><th>Subject</th><th>Sender</th><th>Verdict</th>
                <th>Severity</th><th>Score</th><th>Status</th><th>Notes</th><th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {cases.map(c => (
                <tr key={c.id}>
                  <td className="font-mono text-xs text-cyber-cyan">{c.case_number}</td>
                  <td className="max-w-[150px] truncate text-sm">{c.email_subject || '—'}</td>
                  <td className="text-xs text-gray-400 max-w-[120px] truncate">{c.email_sender || '—'}</td>
                  <td><SeverityBadge severity={c.verdict} /></td>
                  <td><SeverityBadge severity={c.severity} /></td>
                  <td className="font-mono font-semibold text-sm">{c.risk_score?.toFixed(0) || '—'}</td>
                  <td>
                    {editingId === c.id ? (
                      <select value={editStatus} onChange={e => setEditStatus(e.target.value)}
                        className="bg-navy-900 border border-navy-700 rounded px-2 py-1 text-xs text-gray-300">
                        {['new','in_progress','completed','escalated','closed'].map(s =>
                          <option key={s} value={s}>{s.replace('_',' ')}</option>
                        )}
                      </select>
                    ) : (
                      <span className="badge badge-info">{c.status}</span>
                    )}
                  </td>
                  <td className="max-w-[120px]">
                    {editingId === c.id ? (
                      <input value={editNotes} onChange={e => setEditNotes(e.target.value)}
                        className="bg-navy-900 border border-navy-700 rounded px-2 py-1 text-xs text-gray-300 w-full" placeholder="Analyst notes..." />
                    ) : (
                      <span className="text-xs text-gray-500 truncate block">{c.analyst_notes || '—'}</span>
                    )}
                  </td>
                  <td>
                    <div className="flex gap-1">
                      {editingId === c.id ? (
                        <>
                          <button onClick={() => handleSave(c.id)} className="p-1.5 rounded-lg hover:bg-green-500/10 text-green-400"><Save className="w-3.5 h-3.5" /></button>
                          <button onClick={() => setEditingId(null)} className="p-1.5 rounded-lg hover:bg-gray-500/10 text-gray-400"><X className="w-3.5 h-3.5" /></button>
                        </>
                      ) : (
                        <>
                          <button onClick={() => handleEdit(c)} className="p-1.5 rounded-lg hover:bg-blue-500/10 text-blue-400 text-[10px]">Edit</button>
                          <button onClick={() => handleDelete(c.id)} className="p-1.5 rounded-lg hover:bg-red-500/10 text-red-400"><Trash2 className="w-3.5 h-3.5" /></button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
