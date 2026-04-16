import { useState } from 'react'

import { ChainGraph } from '../components/ChainGraph'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { api, apiBase } from '../lib/api'
import type { RunResult } from '../lib/types'

export function ResultsComparePage({ runId }: { runId: string }) {
  const [results, setResults] = useState<RunResult[]>([])
  const [status, setStatus] = useState<string>('idle')

  async function refresh() {
    if (!runId) return
    const detail = await api<{ status: string; result?: { results: RunResult[] } }>(`/api/runs/${runId}`)
    setStatus(detail.status)
    setResults(detail.result?.results ?? [])
  }

  const best = [...results].sort((a, b) => b.policy_score - a.policy_score)[0]

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Results Compare</h2>
      <Card>
        <div className="flex items-center gap-2">
          <Button onClick={() => void refresh()} disabled={!runId}>
            Refresh run status
          </Button>
          {runId && (
            <a
              className="rounded-md border px-3 py-2 text-sm"
              href={`${apiBase()}/api/runs/${runId}/export.zip`}
              target="_blank"
            >
              Download export.zip
            </a>
          )}
        </div>
        <p className="mt-2 text-xs">Status: {status}</p>
      </Card>
      <div className="grid gap-3 md:grid-cols-2">
        {results.map((result) => (
          <Card key={result.provider}>
            <h3 className="text-sm font-semibold">{result.provider}</h3>
            <p className="text-xs">latency: {result.latency_ms.toFixed(2)} ms</p>
            <p className="text-xs">policy score: {result.policy_score}</p>
            <p className="text-xs">schema valid: {String(result.schema_valid)}</p>
            <p className="text-xs">coherent: {String(result.coherent)}</p>
          </Card>
        ))}
      </div>
      {best && (
        <Card>
          <h3 className="mb-2 text-sm font-semibold">Best chain preview ({best.provider})</h3>
          <ChainGraph functions={['gateway', 'waf', 'firewall', 'ids', 'service']} />
        </Card>
      )}
    </div>
  )
}
