export function createPipelineSocket(url = 'ws://localhost:8000/ws') {
  return new WebSocket(url);
}
