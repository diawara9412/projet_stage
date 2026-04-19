import React from 'react';
import { Link, Route, Routes } from 'react-router-dom';
import HomePage from './pages/HomePage';
import SimulationPage from './pages/SimulationPage';
import GenerationPage from './pages/GenerationPage';
import ResultsPage from './pages/ResultsPage';
import EvaluationPage from './pages/EvaluationPage';

export default function App() {
  return (
    <div className="app">
      <nav className="nav">
        <Link to="/">Dashboard</Link>
        <Link to="/simulation">Simulation</Link>
        <Link to="/generation">Generation</Link>
        <Link to="/results">Results</Link>
        <Link to="/evaluation">Evaluation</Link>
      </nav>
      <main>
        <Routes>
          <Route path="/" element={<HomePage />} />
          <Route path="/simulation" element={<SimulationPage />} />
          <Route path="/generation" element={<GenerationPage />} />
          <Route path="/results" element={<ResultsPage />} />
          <Route path="/evaluation" element={<EvaluationPage />} />
        </Routes>
      </main>
    </div>
  );
}
