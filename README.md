# OfSec Vector Triangulum V3

**Advanced Cybersecurity Operations Platform**

> Recon • Vulnerability Scanning • Attack Simulation • AI/ML Analysis • Defense Automation

---

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your API keys

# 2. Start all services
docker-compose up -d

# 3. Verify
curl http://localhost:8000/health
open http://localhost:3000
```

## Architecture

| Service | Port | Description |
|---|---|---|
| **Backend** (FastAPI) | 8000 | REST API + WebSocket |
| **Frontend** (Next.js 15) | 3000 | Dashboard UI |
| **PostgreSQL 17** + TimescaleDB | 5432 | Primary database |
| **Redis 7** | 6379 | Task broker + cache |
| **Qdrant** | 6333/6334 | Vector database (REST/gRPC) |
| **Prometheus** | 9090 | Metrics collection |
| **Nginx** | 80 | Reverse proxy |

## Tech Stack

- **Backend:** Python 3.12, FastAPI, Taskiq, SQLAlchemy, Alembic
- **AI/ML:** PyTorch 2.6+ (torch.compile), LangGraph, LlamaIndex, CrewAI
- **Vector DB:** Qdrant (Rust) + FAISS
- **Frontend:** Next.js 15, React 19, Shadcn/UI, Three.js, D3.js
- **Observability:** OpenTelemetry, Prometheus, structlog

## API Docs

- Swagger: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

## Project Structure

```
ofsec/
├── backend/          # FastAPI + Taskiq workers
├── frontend/         # Next.js 15 dashboard
├── ml/               # ML model training & data
├── infra/            # Docker configs
└── docs/             # Documentation
```

## License

Proprietary — All rights reserved.
