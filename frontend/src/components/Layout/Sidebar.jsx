import { NavLink } from 'react-router-dom'
import { Shield, Search, FolderOpen, Settings, Activity } from 'lucide-react'

const navItems = [
  { to: '/', label: 'Dashboard', icon: Activity },
  { to: '/analyze', label: 'Analyze Email', icon: Search },
  { to: '/cases', label: 'Cases', icon: FolderOpen },
  { to: '/yara', label: 'YARA Rules', icon: Shield },
  { to: '/settings', label: 'Settings', icon: Settings },
]

export default function Sidebar() {
  return (
    <aside className="fixed top-0 left-0 h-screen w-64 flex flex-col border-r border-navy-700/50 bg-navy-900/90 backdrop-blur-xl z-50">
      {/* Logo */}
      <div className="flex items-center gap-3 px-6 py-6 border-b border-navy-700/30">
        <div className="p-2 rounded-xl bg-gradient-to-br from-cyber-blue/20 to-cyber-purple/20 border border-cyber-blue/30">
          <Shield className="w-6 h-6 text-cyber-cyan" />
        </div>
        <div>
          <h1 className="text-sm font-bold text-white tracking-tight">Email Analyzer</h1>
          <p className="text-[10px] text-navy-500 font-medium uppercase tracking-widest">SOC Tool v2.0</p>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {navItems.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `sidebar-link ${isActive ? 'active' : ''}`
            }
            end={to === '/'}
          >
            <Icon className="w-[18px] h-[18px]" />
            <span>{label}</span>
          </NavLink>
        ))}
      </nav>

      {/* Status */}
      <div className="px-4 py-4 border-t border-navy-700/30">
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-severity-safe animate-pulse" />
          <span className="text-xs text-navy-500">System Online</span>
        </div>
      </div>
    </aside>
  )
}
