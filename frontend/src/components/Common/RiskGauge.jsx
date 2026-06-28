import { useEffect, useState } from 'react'

const COLORS = {
  safe: '#22c55e',
  low: '#3b82f6',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
}

function getColor(score) {
  if (score >= 80) return COLORS.critical
  if (score >= 61) return COLORS.high
  if (score >= 40) return COLORS.medium
  if (score >= 20) return COLORS.low
  return COLORS.safe
}

export default function RiskGauge({ score = 0, verdict = 'clean', size = 180 }) {
  const [animatedScore, setAnimatedScore] = useState(0)
  const radius = (size - 20) / 2
  const circumference = 2 * Math.PI * radius
  const color = getColor(score)

  useEffect(() => {
    const timer = setTimeout(() => setAnimatedScore(score), 100)
    return () => clearTimeout(timer)
  }, [score])

  const offset = circumference - (animatedScore / 100) * circumference

  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          {/* Background circle */}
          <circle
            cx={size / 2} cy={size / 2} r={radius}
            stroke="rgba(59, 130, 246, 0.1)" strokeWidth="10" fill="none"
          />
          {/* Score arc */}
          <circle
            cx={size / 2} cy={size / 2} r={radius}
            stroke={color} strokeWidth="10" fill="none"
            strokeLinecap="round"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            className="risk-gauge-circle"
            style={{ filter: `drop-shadow(0 0 8px ${color}40)` }}
          />
        </svg>
        {/* Center text */}
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-4xl font-bold" style={{ color }}>{Math.round(animatedScore)}</span>
          <span className="text-[10px] text-gray-500 uppercase tracking-widest mt-1">Risk Score</span>
        </div>
      </div>
      <div className={`px-4 py-1.5 rounded-full text-xs font-bold uppercase tracking-wider verdict-${verdict}`}>
        {verdict}
      </div>
    </div>
  )
}
