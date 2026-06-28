import { useState, useEffect } from 'react'
import { getSettings, updateSettings } from '../api/client'
import { Settings, Key, Sliders, CheckCircle, XCircle } from 'lucide-react'

export default function SettingsPage() {
  const [settings, setSettingsData] = useState(null)
  const [keys, setKeys] = useState({
    virustotal: '', urlscan: '', abuseipdb: '', alienvault: '', safebrowsing: '',
    m365_tenant_id: '', m365_client_id: '', m365_client_secret: '',
  })
  const [saved, setSaved] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => { loadSettings() }, [])

  const loadSettings = async () => {
    try {
      const data = await getSettings()
      setSettingsData(data)
    } catch { /* offline */ }
    finally { setLoading(false) }
  }

  const handleSaveKeys = async () => {
    const payload = {}
    if (keys.virustotal) payload.virustotal_api_key = keys.virustotal
    if (keys.urlscan) payload.urlscan_api_key = keys.urlscan
    if (keys.abuseipdb) payload.abuseipdb_api_key = keys.abuseipdb
    if (keys.alienvault) payload.alienvault_otx_api_key = keys.alienvault
    if (keys.safebrowsing) payload.google_safebrowsing_api_key = keys.safebrowsing
    if (keys.m365_tenant_id) payload.m365_tenant_id = keys.m365_tenant_id
    if (keys.m365_client_id) payload.m365_client_id = keys.m365_client_id
    if (keys.m365_client_secret) payload.m365_client_secret = keys.m365_client_secret
    if (Object.keys(payload).length === 0) return
    try {
      await updateSettings(payload)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
      loadSettings()
      setKeys({ virustotal: '', urlscan: '', abuseipdb: '', alienvault: '', safebrowsing: '', m365_tenant_id: '', m365_client_id: '', m365_client_secret: '' })
    } catch { /* error */ }
  }

  const apiKeyFields = [
    { key: 'virustotal', label: 'VirusTotal', service: 'VirusTotal' },
    { key: 'urlscan', label: 'URLScan.io', service: 'URLScan.io' },
    { key: 'abuseipdb', label: 'AbuseIPDB', service: 'AbuseIPDB' },
    { key: 'alienvault', label: 'AlienVault OTX', service: 'AlienVault OTX' },
    { key: 'safebrowsing', label: 'Google Safe Browsing', service: 'Google Safe Browsing' },
  ]

  const m365Fields = [
    { key: 'm365_tenant_id', label: 'Tenant ID', service: 'Tenant ID' },
    { key: 'm365_client_id', label: 'Client ID', service: 'Client ID' },
    { key: 'm365_client_secret', label: 'Client Secret', service: 'Client Secret' },
  ]

  return (
    <div className="space-y-6 animate-fade-in max-w-3xl">
      <div>
        <h1 className="text-2xl font-bold text-white">Settings</h1>
        <p className="text-sm text-gray-500 mt-1">Configure API keys and risk scoring parameters</p>
      </div>

      {saved && (
        <div className="p-3 rounded-xl bg-green-500/10 border border-green-500/30 text-green-400 text-sm flex items-center gap-2">
          <CheckCircle className="w-4 h-4" /> Settings saved successfully
        </div>
      )}

      {/* API Keys */}
      <div className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Key className="w-5 h-5 text-cyber-cyan" />
          <h2 className="text-lg font-semibold text-white">API Keys</h2>
        </div>
        <p className="text-xs text-gray-500">All integrations are optional. Add keys to enable threat intelligence enrichment.</p>

        {apiKeyFields.map(({ key, label, service }) => {
          const configured = settings?.api_keys?.find(k => k.service === service)?.is_configured
          return (
            <div key={key} className="flex items-center gap-3">
              <div className="w-40 flex items-center gap-2">
                {configured ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <XCircle className="w-3.5 h-3.5 text-gray-600" />}
                <span className="text-sm text-gray-300">{label}</span>
              </div>
              <input
                type="password"
                value={keys[key]}
                onChange={e => setKeys(k => ({...k, [key]: e.target.value}))}
                placeholder={configured ? '••••••• (configured)' : 'Enter API key...'}
                className="flex-1 bg-navy-900 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-300 placeholder-gray-600 focus:border-cyber-blue/50 focus:outline-none font-mono"
              />
            </div>
          )
        })}

        <button onClick={handleSaveKeys} className="btn-primary mt-2">Save API Keys</button>
      </div>

      {/* M365 SOAR Settings */}
      <div className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-2 mb-2">
          <Key className="w-5 h-5 text-cyber-purple" />
          <h2 className="text-lg font-semibold text-white">Microsoft 365 Integration (SOAR)</h2>
        </div>
        <p className="text-xs text-gray-500">Configure credentials to enable automated email purging.</p>

        {m365Fields.map(({ key, label, service }) => {
          const configured = settings?.m365_config?.find(k => k.service === service)?.is_configured
          return (
            <div key={key} className="flex items-center gap-3">
              <div className="w-40 flex items-center gap-2">
                {configured ? <CheckCircle className="w-3.5 h-3.5 text-green-400" /> : <XCircle className="w-3.5 h-3.5 text-gray-600" />}
                <span className="text-sm text-gray-300">{label}</span>
              </div>
              <input
                type="password"
                value={keys[key]}
                onChange={e => setKeys(k => ({...k, [key]: e.target.value}))}
                placeholder={configured ? '••••••• (configured)' : 'Enter value...'}
                className="flex-1 bg-navy-900 border border-navy-700/50 rounded-lg px-3 py-2 text-sm text-gray-300 placeholder-gray-600 focus:border-cyber-blue/50 focus:outline-none font-mono"
              />
            </div>
          )
        })}

        <button onClick={handleSaveKeys} className="btn-primary mt-2">Save M365 Settings</button>
      </div>

      {/* Risk Weights */}
      {settings?.risk_weights && (
        <div className="glass-card p-6 space-y-4">
          <div className="flex items-center gap-2 mb-2">
            <Sliders className="w-5 h-5 text-cyber-purple" />
            <h2 className="text-lg font-semibold text-white">Risk Scoring Weights</h2>
          </div>
          <p className="text-xs text-gray-500">Current weights (edit in .env for persistent changes)</p>
          <div className="grid grid-cols-2 gap-3">
            {Object.entries(settings.risk_weights).map(([key, value]) => (
              <div key={key} className="flex items-center justify-between p-3 rounded-lg bg-navy-800/30 border border-navy-700/20">
                <span className="text-sm text-gray-400 capitalize">{key.replace(/_/g, ' ')}</span>
                <span className="text-sm font-bold text-white">{value}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* App Info */}
      <div className="glass-card p-6">
        <div className="flex items-center gap-2 mb-2">
          <Settings className="w-5 h-5 text-gray-500" />
          <h2 className="text-lg font-semibold text-white">Application</h2>
        </div>
        <div className="grid grid-cols-2 gap-3 text-sm">
          <div><span className="text-gray-500">Version:</span> <span className="text-gray-300">1.0.0</span></div>
          <div><span className="text-gray-500">Max Upload:</span> <span className="text-gray-300">{settings?.max_upload_size_mb || 25} MB</span></div>
        </div>
      </div>
    </div>
  )
}
