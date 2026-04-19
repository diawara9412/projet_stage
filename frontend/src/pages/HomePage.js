import React from 'react';
import OverviewCard from '../components/Dashboard/OverviewCard';
import Layout from '../components/common/Layout';

export default function HomePage() {
  return (
    <Layout title="Dashboard principal">
      <div className="grid">
        <OverviewCard title="Datasets" value="CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15" />
        <OverviewCard title="LLMs" value="GPT, Claude, Mistral, LLaMA" />
        <OverviewCard title="Execution" value="Real-time monitoring ready" />
      </div>
    </Layout>
  );
}
