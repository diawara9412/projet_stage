import { useEffect, useState } from 'react'
import { ModelSelector } from '../components/ModelSelector'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { api } from '../lib/api'
import type { ModelAvailability } from '../lib/types'

export function BenchmarkRunnerPage({
  uploadId,
  runId,
  setRunId,
}: {
  uploadId: string
  runId: string
  setRunId: (id: string) => void
}) {
  const [models, setModels] = useState<ModelAvailability[]>([])
  const [selected, setSelected] = useState<string[]>(['llama_ollama'])

  useEffect(() => {
    void api<{ models: ModelAvailability[] }>('/api/models').then((payload) => setModels(payload.models))
  }, [])

  async function launch() {
    const payload = await api<{ run_id: string }>('/api/runs', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ upload_id: uploadId, models: selected, repeats: 1 }),
    })
    setRunId(payload.run_id)
  }

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Benchmark Runner</h2>
      <ModelSelector models={models} selected={selected} onChange={setSelected} />
      <Card>
        <Button onClick={() => void launch()} disabled={!uploadId || selected.length === 0}>
          Launch benchmark
        </Button>
        <p className="mt-2 text-xs">Current run: {runId || 'none'}</p>
      </Card>
    </div>
  )
}
