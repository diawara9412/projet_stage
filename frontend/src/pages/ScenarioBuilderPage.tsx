import YAML from 'yaml'
import type { FlowRecord } from '../lib/types'
import { YamlViewer } from '../components/YamlViewer'

export function ScenarioBuilderPage({ flows }: { flows: FlowRecord[] }) {
  const scenario = {
    zones: {
      internal: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
      dmz: ['100.64.0.0/10'],
      external: ['0.0.0.0/0'],
    },
    aggregated_flows: flows,
    security_requirements: [
      {
        id: 'ingress-web',
        must_include_functions_in_order: ['waf', 'firewall'],
      },
      {
        id: 'sensitive-ids',
        must_include_functions_in_order: ['ids'],
      },
    ],
  }

  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Scenario Builder</h2>
      <YamlViewer value={YAML.stringify(scenario)} />
    </div>
  )
}
