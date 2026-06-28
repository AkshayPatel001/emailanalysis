export default function LoadingSpinner({ text = 'Analyzing...' }) {
  return (
    <div className="flex flex-col items-center justify-center py-20 gap-4">
      <div className="spinner" />
      <p className="text-sm text-gray-400 animate-pulse">{text}</p>
    </div>
  )
}
