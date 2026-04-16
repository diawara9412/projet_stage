import { Card } from './ui/card'

export function YamlViewer({ value }: { value: string }) {
  return (
    <Card>
      <h3 className="mb-2 text-sm font-semibold">YAML Viewer</h3>
      <pre className="max-h-[300px] overflow-auto rounded bg-slate-100 p-3 text-xs dark:bg-slate-950">{value}</pre>
    </Card>
  )
}
