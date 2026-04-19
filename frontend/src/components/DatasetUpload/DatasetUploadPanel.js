import React from 'react';

export default function DatasetUploadPanel() {
  return (
    <section className="card">
      <h2>Upload traces</h2>
      <p>PCAP, NetFlow ou CSV.</p>
      <input type="file" />
    </section>
  );
}
