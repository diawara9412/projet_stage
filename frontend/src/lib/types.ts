export type ModelAvailability = { name: string; available: boolean }

export type FlowRecord = {
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  bytes: number
  packets: number
  tags?: string[]
  app_hint?: string
}

export type RunResult = {
  provider: string
  available: boolean
  latency_ms: number
  schema_valid: boolean
  policy_score: number
  coherent: boolean
  issues: string[]
  plan_path: string
}
