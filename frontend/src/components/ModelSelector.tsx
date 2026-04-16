import type { ModelAvailability } from '../lib/types'
import { Badge } from './ui/badge'
import { Card } from './ui/card'

export function ModelSelector({
  models,
  selected,
  onChange,
}: {
  models: ModelAvailability[]
  selected: string[]
  onChange: (value: string[]) => void
}) {
  function toggle(name: string) {
    if (selected.includes(name)) onChange(selected.filter((item) => item !== name))
    else onChange([...selected, name])
  }

  return (
    <Card>
      <h3 className="mb-2 text-sm font-semibold">Model selector</h3>
      <div className="space-y-2">
        {models.map((model) => (
          <label key={model.name} className="flex items-center justify-between rounded border p-2 text-sm">
            <span className="flex items-center gap-2">
              <input
                type="checkbox"
                checked={selected.includes(model.name)}
                onChange={() => toggle(model.name)}
              />
              {model.name}
            </span>
            <Badge>{model.available ? 'available' : 'disabled'}</Badge>
          </label>
        ))}
      </div>
    </Card>
  )
}
