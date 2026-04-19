import React from 'react';

export default function RuleConfigPanel({ provider, onProviderChange }) {
  return (
    <section className="card">
      <h2>LLM Configuration</h2>
      <label htmlFor="provider">Provider</label>
      <select id="provider" value={provider} onChange={(e) => onProviderChange(e.target.value)}>
        <option value="gpt">GPT</option>
        <option value="claude">Claude</option>
        <option value="mistral">Mistral</option>
        <option value="llama">LLaMA</option>
      </select>
    </section>
  );
}
