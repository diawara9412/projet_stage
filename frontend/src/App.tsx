import { useEffect, useState } from 'react'
import { BrowserRouter, NavLink, Route, Routes } from 'react-router-dom'
import { BenchmarkRunnerPage } from './pages/BenchmarkRunnerPage'
import { FlowsExplorerPage } from './pages/FlowsExplorerPage'
import { ResultsComparePage } from './pages/ResultsComparePage'
import { ScenarioBuilderPage } from './pages/ScenarioBuilderPage'
import { UploadPage } from './pages/UploadPage'
import type { FlowRecord } from './lib/types'

const tabs = [
  ['/', 'Upload'],
  ['/flows', 'Flows Explorer'],
  ['/scenario', 'Scenario Builder'],
  ['/benchmark', 'Benchmark Runner'],
  ['/results', 'Results Compare'],
] as const

function AppShell() {
  const [uploadId, setUploadId] = useState('')
  const [runId, setRunId] = useState('')
  const [flows, setFlows] = useState<FlowRecord[]>([])
  const [dark, setDark] = useState(false)

  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark)
  }, [dark])

  return (
    <div className="mx-auto max-w-6xl space-y-6 p-4">
      <header className="flex flex-wrap items-center justify-between gap-3 rounded-xl border bg-white/90 p-4 dark:bg-slate-900">
        <div>
          <h1 className="text-lg font-semibold">Internship Security Chain Pipeline</h1>
          <p className="text-xs text-slate-500">PCAP/NetFlow → Scenario → Multi-model benchmark → Exportable manifests</p>
        </div>
        <button className="rounded-md border px-3 py-2 text-xs" onClick={() => setDark((v) => !v)}>
          {dark ? 'Light mode' : 'Dark mode'}
        </button>
      </header>

      <nav className="flex flex-wrap gap-2">
        {tabs.map(([to, label]) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              `rounded-full border px-3 py-1 text-sm ${isActive ? 'bg-slate-900 text-white dark:bg-slate-100 dark:text-slate-900' : ''}`
            }
          >
            {label}
          </NavLink>
        ))}
      </nav>

      <Routes>
        <Route path="/" element={<UploadPage uploadId={uploadId} setUploadId={setUploadId} />} />
        <Route path="/flows" element={<FlowsExplorerPage uploadId={uploadId} setFlows={setFlows} />} />
        <Route path="/scenario" element={<ScenarioBuilderPage flows={flows} />} />
        <Route path="/benchmark" element={<BenchmarkRunnerPage uploadId={uploadId} runId={runId} setRunId={setRunId} />} />
        <Route path="/results" element={<ResultsComparePage runId={runId} />} />
      </Routes>
    </div>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <AppShell />
    </BrowserRouter>
  )
}
