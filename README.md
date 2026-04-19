# Pipeline Complet - Génération Automatique de Chaînes de Sécurité via LLM

Projet full-stack (FastAPI + React) pour générer, traduire et évaluer des règles de sécurité à partir de traces réseau réelles ou simulées, avec comparaison inter-LLMs (GPT, Claude, Mistral, LLaMA).

## Architecture

- **Backend**: `backend/`
  - Gestion datasets (CIC-IDS2017/CSE-CIC-IDS2018/UNSW-NB15)
  - Parsing PCAP/NetFlow + simulation trafic (Scapy/Mininet stub)
  - Intégration multi-LLM via factory providers
  - Génération règles abstraites + formats concrets (OpenFlow, Snort, iptables, DLP)
  - Évaluation (relevance, précision, rappel, F1, timing)
- **Frontend**: `frontend/`
  - Dashboard, simulation/upload, configuration, résultats, analytics
  - Hooks API, services export, base UI responsive

## Lancement rapide

### Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm start
```

### Docker Compose

```bash
docker compose up --build
```

## Configuration LLM (clés API)

Renseigner `backend/.env.example` (ou un vrai `.env`) :

- `OPENROUTER_API_KEY` (GPT via OpenRouter)
- `ANTHROPIC_API_KEY` (Claude)
- `MISTRAL_API_KEY` (Mistral)
- `HUGGINGFACE_API_KEY` / `OLLAMA_BASE_URL` (LLaMA)

Si une clé est absente, le backend renvoie un résultat mock pour garder le pipeline exécutable.

## Tests

```bash
cd backend
python -m unittest -q
```
