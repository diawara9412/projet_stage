import { useState } from 'react'
import { FlowsTable } from '../components/FlowsTable'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { api } from '../lib/api'
import type { FlowRecord } from '../lib/types'

export function FlowsExplorerPage({ uploadId, setFlows }: { uploadId: string; setFlows: (flows: FlowRecord[]) => void }) {
  const [flows, localSetFlows] = useState<FlowRecord[]>([])

  async function parseUpload() {
    if (!uploadId) return
    await api(`/api/uploads/${uploadId}/parse`, { method: 'POST' })
    const scenario = await api<{ scenario: { aggregated_flows: FlowRecord[] } }>(`/api/uploads/${uploadId}/scenario`, {
      method: 'POST',
    })
    localSetFlows(scenario.scenario.aggregated_flows)
    setFlows(scenario.scenario.aggregated_flows)
  }

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Flows Explorer</h2>
      <Card>
        <Button onClick={() => void parseUpload()} disabled={!uploadId}>
          Parse upload & build scenario
        </Button>
      </Card>
      <FlowsTable flows={flows} />
    </div>
  )
}
