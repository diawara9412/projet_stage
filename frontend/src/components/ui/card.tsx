import type { PropsWithChildren } from 'react'

export function Card({ children }: PropsWithChildren) {
  return <div className="rounded-xl border bg-white/90 p-4 shadow-sm dark:bg-slate-900">{children}</div>
}
