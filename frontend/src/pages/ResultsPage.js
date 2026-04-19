import React from 'react';
import Layout from '../components/common/Layout';
import ResultsViewer from '../components/ResultsViewer/ResultsViewer';

export default function ResultsPage() {
  return (
    <Layout title="Résultats">
      <ResultsViewer
        result={{
          abstract: { json: '{"rules":[]}', yaml: 'rules: []' },
          concrete: { snort: 'alert tcp any any -> any any (...)' }
        }}
      />
    </Layout>
  );
}
