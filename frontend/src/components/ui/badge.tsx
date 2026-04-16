import type { PropsWithChildren } from 'react'

export function Badge({ children }: PropsWithChildren) {
  return <span className="inline-flex rounded-full border px-2 py-0.5 text-xs">{children}</span>
}
