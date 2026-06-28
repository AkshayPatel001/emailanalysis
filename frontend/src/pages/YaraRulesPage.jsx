import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { Plus, Trash2, CheckCircle, XCircle } from 'lucide-react';

export default function YaraRulesPage() {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [isAdding, setIsAdding] = useState(false);
  const [newRule, setNewRule] = useState({ rule_name: '', rule_content: 'rule NewRule {\n  strings:\n    $a = "suspicious_string"\n  condition:\n    $a\n}', author: 'SOC Analyst' });

  useEffect(() => {
    fetchRules();
  }, []);

  const fetchRules = async () => {
    try {
      const res = await axios.get('/api/yara');
      setRules(res.data);
    } catch (err) {
      setError('Failed to fetch YARA rules');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async () => {
    try {
      setError(null);
      await axios.post('/api/yara', newRule);
      setIsAdding(false);
      setNewRule({ rule_name: '', rule_content: 'rule NewRule {\n  strings:\n    $a = "suspicious_string"\n  condition:\n    $a\n}', author: 'SOC Analyst' });
      fetchRules();
    } catch (err) {
      setError(err.response?.data?.detail || 'Failed to create rule. Check syntax.');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm("Delete this YARA rule?")) return;
    try {
      await axios.delete(`/api/yara/${id}`);
      fetchRules();
    } catch (err) {
      setError('Failed to delete rule');
    }
  };

  const toggleActive = async (id, currentStatus) => {
    try {
      await axios.patch(`/api/yara/${id}`, { is_active: !currentStatus });
      fetchRules();
    } catch (err) {
      setError('Failed to update rule');
    }
  };

  if (loading) return <div className="text-gray-400 p-8">Loading YARA rules...</div>;

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-3xl font-bold tracking-tight text-white drop-shadow-sm">YARA Rules Engine</h1>
          <p className="mt-2 text-sm text-gray-400">Manage custom threat hunting rules applied during analysis.</p>
        </div>
        <button
          onClick={() => setIsAdding(!isAdding)}
          className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-4 py-2 text-sm font-semibold text-white shadow-sm hover:bg-blue-500"
        >
          <Plus className="h-5 w-5" />
          {isAdding ? 'Cancel' : 'New Rule'}
        </button>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-500/50 rounded-md p-4 text-red-200">
          {error}
        </div>
      )}

      {isAdding && (
        <div className="bg-gray-800 border border-gray-700 rounded-xl p-6 shadow-xl space-y-4">
          <h2 className="text-lg font-medium text-white">Create New YARA Rule</h2>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Rule Name (Must match YARA identifier)</label>
              <input
                type="text"
                className="w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-white focus:ring-blue-500 focus:border-blue-500"
                value={newRule.rule_name}
                onChange={(e) => setNewRule({...newRule, rule_name: e.target.value})}
                placeholder="e.g. Detect_Malicious_Macro"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Author</label>
              <input
                type="text"
                className="w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-white focus:ring-blue-500 focus:border-blue-500"
                value={newRule.author}
                onChange={(e) => setNewRule({...newRule, author: e.target.value})}
              />
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">YARA Syntax</label>
            <textarea
              rows={8}
              className="w-full font-mono text-sm bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-green-400 focus:ring-blue-500 focus:border-blue-500"
              value={newRule.rule_content}
              onChange={(e) => setNewRule({...newRule, rule_content: e.target.value})}
            />
          </div>
          <div className="flex justify-end">
            <button
              onClick={handleCreate}
              className="bg-green-600 text-white px-4 py-2 rounded-md hover:bg-green-500 font-medium"
            >
              Compile & Save
            </button>
          </div>
        </div>
      )}

      <div className="bg-gray-800/50 backdrop-blur-sm border border-gray-700/50 rounded-xl shadow-2xl overflow-hidden ring-1 ring-white/5">
        <table className="min-w-full divide-y divide-gray-700/50">
          <thead>
            <tr className="bg-gray-900/50">
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-300 uppercase tracking-wider">Status</th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-300 uppercase tracking-wider">Rule Name</th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-300 uppercase tracking-wider">Author</th>
              <th className="px-6 py-4 text-left text-xs font-semibold text-gray-300 uppercase tracking-wider">Updated</th>
              <th className="px-6 py-4 text-right text-xs font-semibold text-gray-300 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-700/50">
            {rules.length === 0 ? (
              <tr>
                <td colSpan="5" className="px-6 py-8 text-center text-sm text-gray-400">
                  No YARA rules defined. Create one to start threat hunting!
                </td>
              </tr>
            ) : (
              rules.map((rule) => (
                <tr key={rule.id} className="hover:bg-gray-800/80 transition-colors">
                  <td className="px-6 py-4 whitespace-nowrap">
                    <button onClick={() => toggleActive(rule.id, rule.is_active)} className="focus:outline-none">
                      {rule.is_active ? (
                        <span className="inline-flex items-center gap-1 rounded-full bg-green-500/10 px-2 py-1 text-xs font-medium text-green-400 ring-1 ring-inset ring-green-500/20">
                          <CheckCircle className="w-3 h-3" /> Active
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded-full bg-gray-500/10 px-2 py-1 text-xs font-medium text-gray-400 ring-1 ring-inset ring-gray-500/20">
                          <XCircle className="w-3 h-3" /> Disabled
                        </span>
                      )}
                    </button>
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-white font-mono">
                    {rule.rule_name}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {rule.author}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                    {new Date(rule.updated_at).toLocaleString()}
                  </td>
                  <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button 
                      onClick={() => handleDelete(rule.id)}
                      className="text-red-400 hover:text-red-300 p-1 rounded-md hover:bg-red-400/10 transition-colors"
                      title="Delete Rule"
                    >
                      <Trash2 className="h-5 w-5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
