import { useRef, useState } from 'react'
import { Button } from './ui/button'
import { Card } from './ui/card'

type Props = {
  onUploaded: (uploadId: string) => void
}

export function DragDropUpload({ onUploaded }: Props) {
  const inputRef = useRef<HTMLInputElement>(null)
  const [busy, setBusy] = useState(false)

  async function submit(file: File) {
    setBusy(true)
    try {
      const body = new FormData()
      body.append('file', file)
      const response = await fetch(`${import.meta.env.VITE_API_BASE ?? 'http://localhost:8000'}/api/uploads`, {
        method: 'POST',
        body,
      })
      const payload = await response.json()
      if (!response.ok) throw new Error(payload.detail || 'Upload failed')
      onUploaded(payload.upload_id)
    } finally {
      setBusy(false)
    }
  }

  return (
    <Card>
      <div
        className="rounded-lg border-2 border-dashed p-8 text-center"
        onDragOver={(event) => event.preventDefault()}
        onDrop={(event) => {
          event.preventDefault()
          const file = event.dataTransfer.files.item(0)
          if (file) void submit(file)
        }}
      >
        <p className="mb-4">Drag & drop PCAP / NetFlow CSV / NetFlow JSON</p>
        <input
          ref={inputRef}
          hidden
          type="file"
          accept=".pcap,.pcapng,.csv,.json"
          onChange={(event) => {
            const file = event.target.files?.item(0)
            if (file) void submit(file)
          }}
        />
        <Button disabled={busy} onClick={() => inputRef.current?.click()}>
          {busy ? 'Uploading…' : 'Select file'}
        </Button>
      </div>
    </Card>
  )
}
