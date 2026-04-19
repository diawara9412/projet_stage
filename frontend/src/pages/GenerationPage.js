import React, { useState } from 'react';
import Layout from '../components/common/Layout';
import RuleConfigPanel from '../components/RuleConfiguration/RuleConfigPanel';

export default function GenerationPage() {
  const [provider, setProvider] = useState('gpt');

  return (
    <Layout title="Configuration des règles">
      <RuleConfigPanel provider={provider} onProviderChange={setProvider} />
      <p className="card">Provider sélectionné : {provider}</p>
    </Layout>
  );
}
