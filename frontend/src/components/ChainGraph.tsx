import 'reactflow/dist/style.css'
import { Background, Controls, ReactFlow } from 'reactflow'

export function ChainGraph({ functions }: { functions: string[] }) {
  const nodes = functions.map((label, index) => ({
    id: `${index}`,
    data: { label },
    position: { x: index * 150, y: 50 },
  }))
  const edges = functions.slice(1).map((_, index) => ({ id: `e${index}`, source: `${index}`, target: `${index + 1}` }))

  return (
    <div className="h-[220px] rounded border">
      <ReactFlow nodes={nodes} edges={edges} fitView>
        <Background />
        <Controls />
      </ReactFlow>
    </div>
  )
}
