export function validateProvider(provider) {
  return ['gpt', 'claude', 'mistral', 'llama'].includes(provider);
}
