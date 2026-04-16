# Internship Security Chain Pipeline (Option C)

Full-stack project to upload **PCAP** and **NetFlow (CSV/JSON V1)** files, build a `scenario.yaml`, run multi-model plan generation, render deployable Kubernetes manifests, evaluate outputs, and compare results in a React UI.

## Stack
- **Backend:** FastAPI, SQLite, Scapy, Jinja2
- **Frontend:** React + TypeScript + Vite, Tailwind CSS, React Flow
- **Providers (plugin architecture):**
  - Llama local via Ollama (`llama_ollama`)
  - Optional API providers (auto-disabled without keys): Mistral, OpenAI GPT-4.1, Anthropic Claude

---

## Project structure

- `backend/app/main.py` API endpoints
- `backend/app/services/parsers.py` PCAP/NetFlow parsing (pure Python for PCAP using Scapy)
- `backend/app/services/scenario.py` scenario generation
- `backend/app/llm_providers/providers.py` provider plugins and availability
- `backend/app/services/renderer.py` Jinja2 Kubernetes manifest rendering
- `backend/app/services/evaluators.py` metrics/evaluation
- `frontend/` React UI pages/components
- `samples/netflow/` NetFlow V1 schema + sample files
- `data/` runtime uploads/runs/artifacts (gitignored)

---

## Requirements implemented

### Ingestion
- Upload PCAP (`.pcap` / `.pcapng`) parsed with **Scapy** (no tshark)
- Upload NetFlow CSV/JSON V1 with schema and sample files
- Artifacts stored under `data/`, metadata persisted in SQLite (`data/metadata.db`)

### Scenario generation
`POST /api/uploads/{upload_id}/scenario` generates `scenario.yaml` with:
- zones (CIDR lists)
- aggregated flows + tags + app hints
- security requirements derived from simple rules
- function catalog (waf/firewall/ids, images, ports)
- output constraints

### Generation approach
- LLM/provider output is a **structured JSON plan** (chains + selectors)
- Backend renders deployable manifests via Jinja2 templates:
  - Namespace
  - Deployment/Service per function
  - Gateway + HTTPRoute + TCPRoute placeholders
  - `README-deploy.md` for kind deployment
- `GET /api/runs/{id}/export.zip` contains scenario + plan(s) + manifests + metrics

### Evaluation
Per provider:
- JSON schema validity
- policy compliance (`must_include_functions_in_order`)
- chain coherence checks
- latency measurement
- metrics emitted as JSON and CSV

---

## API endpoints

- `POST /api/uploads` (multipart)
- `POST /api/uploads/{upload_id}/parse`
- `POST /api/uploads/{upload_id}/scenario`
- `GET /api/models`
- `POST /api/runs`
- `GET /api/runs/{run_id}`
- `GET /api/runs/{run_id}/export.zip`

CORS enabled for frontend dev (`CORS_ORIGINS`, default `http://localhost:5173`).

---

## Local run

### 1) Backend
```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cd ..
uvicorn backend.app.main:app --reload
```

### 2) Frontend
```bash
cd frontend
npm install
npm run dev
```

Frontend default URL: `http://localhost:5173`  
Backend default URL: `http://localhost:8000`

---

## Ollama (recommended baseline)

1. Install/start Ollama locally
2. Pull model:
```bash
ollama pull llama3.1:8b
```
3. Ensure `.env` has:
```env
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b
```

Optional providers are auto-disabled when keys are missing.

---

## kind target deployment notes

```bash
kind create cluster --name sfc-demo
# install Gateway API CRDs if not present
kubectl apply -f <generated-manifests.yaml>
```

Each run export includes `README-deploy.md` with deployment steps.

---

## Tests

```bash
cd backend
python -m pytest tests/test_api_pipeline.py
```

---

## Environment
Copy `.env.example` to `.env` and set what you need.  
No paid keys are required for local workflow with Ollama.
