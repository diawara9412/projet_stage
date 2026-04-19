import { useState } from 'react';

export default function useLLM(defaultProvider = 'gpt') {
  const [provider, setProvider] = useState(defaultProvider);
  return { provider, setProvider };
}
