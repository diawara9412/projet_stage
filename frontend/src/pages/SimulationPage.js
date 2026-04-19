import React from 'react';
import DatasetUploadPanel from '../components/DatasetUpload/DatasetUploadPanel';
import Layout from '../components/common/Layout';

export default function SimulationPage() {
  return (
    <Layout title="Simulation & Upload">
      <DatasetUploadPanel />
    </Layout>
  );
}
