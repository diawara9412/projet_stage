import { DragDropUpload } from '../components/DragDropUpload'
import { Card } from '../components/ui/card'

export function UploadPage({ uploadId, setUploadId }: { uploadId: string; setUploadId: (id: string) => void }) {
  return (
    <div className="space-y-4">
      <h2 className="text-xl font-semibold">Upload</h2>
      <DragDropUpload onUploaded={setUploadId} />
      <Card>
        <p className="text-sm">Current upload: {uploadId || 'none'}</p>
      </Card>
    </div>
  )
}
