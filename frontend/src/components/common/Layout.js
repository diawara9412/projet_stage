import React from 'react';

export default function Layout({ title, children }) {
  return (
    <section>
      <h1>{title}</h1>
      {children}
    </section>
  );
}
