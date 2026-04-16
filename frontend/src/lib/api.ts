const API_BASE = import.meta.env.VITE_API_BASE ?? 'http://localhost:8000'

export async function api<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, init)
  if (!response.ok) {
    const txt = await response.text()
    throw new Error(txt || `HTTP ${response.status}`)
  }
  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) return response.json()
  return response as T
}

export function apiBase() {
  return API_BASE
}
