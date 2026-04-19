import React from 'react';

export default function ResultsViewer({ result }) {
  if (!result) {
    return <p>Aucun résultat pour le moment.</p>;
  }
  return (
    <section className="card">
      <h2>Generated Rules</h2>
      <pre>{JSON.stringify(result, null, 2)}</pre>
    </section>
  );
}
