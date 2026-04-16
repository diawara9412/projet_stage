import type { FlowRecord } from '../lib/types'
import { Card } from './ui/card'

export function FlowsTable({ flows }: { flows: FlowRecord[] }) {
  return (
    <Card>
      <h3 className="mb-3 text-sm font-semibold">Flows ({flows.length})</h3>
      <div className="max-h-[320px] overflow-auto">
        <table className="w-full text-left text-xs">
          <thead>
            <tr>
              <th>Source</th>
              <th>Destination</th>
              <th>Protocol</th>
              <th>Ports</th>
              <th>Bytes</th>
              <th>Tags</th>
            </tr>
          </thead>
          <tbody>
            {flows.map((flow, index) => (
              <tr key={`${flow.src_ip}-${flow.dst_ip}-${index}`} className="border-t">
                <td>{flow.src_ip}</td>
                <td>{flow.dst_ip}</td>
                <td>{flow.protocol}</td>
                <td>
                  {flow.src_port} → {flow.dst_port}
                </td>
                <td>{flow.bytes}</td>
                <td>{flow.tags?.join(', ') || '-'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  )
}
