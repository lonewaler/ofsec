# OfSec V3 — Quick Start Guide

## Prerequisites

| Requirement         | Version    | Check command              |
|---------------------|------------|----------------------------|
| Python              | 3.12+      | `python --version`         |
| pip                 | latest     | `pip --version`            |
| Redis *(optional)*  | 7+         | `redis-cli ping`           |
| PostgreSQL *(optional)* | 15+   | `psql --version`           |

> **Note:** Redis and PostgreSQL are optional for development. The app defaults to SQLite and InMemoryBroker without them.

---

## 3-Command Quick Start

### Windows
```batch
git clone <repo-url> ofsec && cd ofsec
copy backend\.env.example backend\.env
start.bat
```

### Linux / macOS
```bash
git clone <repo-url> ofsec && cd ofsec
cp backend/.env.example backend/.env
chmod +x start.sh stop.sh && bash start.sh
```

The app will be available at:
- **Dashboard:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **Health:** http://localhost:8000/health

Default login: `admin@ofsec.io` / `ChangeMe123!`  
⚠️ **Change this password immediately in production.**

---

## Environment Variables (.env)

| Variable              | Default                            | Description                            |
|-----------------------|------------------------------------|----------------------------------------|
| `ENVIRONMENT`         | `development`                      | `development` or `production`          |
| `DEBUG`               | `true`                             | Enable debug mode (set `false` in prod)|
| `SECRET_KEY`          | `change-me-in-production`          | JWT signing key — **must be unique!**  |
| `API_KEY`             | `dev-api-key`                      | API key for service auth               |
| `LOG_LEVEL`           | `INFO`                             | Logging level (DEBUG/INFO/WARNING)     |
| `DATABASE_URL`        | `sqlite+aiosqlite:///./ofsec.db`   | DB connection string                   |
| `POSTGRES_DB`         | `ofsec`                            | PostgreSQL database name               |
| `POSTGRES_USER`       | `ofsec`                            | PostgreSQL username                    |
| `POSTGRES_PASSWORD`   | `CHANGE_THIS_PASSWORD`             | PostgreSQL password                    |
| `DB_POOL_SIZE`        | `5`                                | SQLAlchemy pool size                   |
| `DB_MAX_OVERFLOW`     | `10`                               | Max overflow connections               |
| `DB_POOL_TIMEOUT`     | `30`                               | Connection timeout (seconds)           |
| `REDIS_URL`           | `redis://localhost:6379/0`         | Redis connection URL                   |
| `GEMINI_API_KEY`      | *(empty)*                          | Google Gemini API key for AI features  |
| `SHODAN_API_KEY`      | *(empty)*                          | Shodan OSINT API key                   |
| `VIRUSTOTAL_API_KEY`  | *(empty)*                          | VirusTotal API key                     |
| `ABUSEIPDB_API_KEY`   | *(empty)*                          | AbuseIPDB API key                      |
| `CENSYS_API_ID`       | *(empty)*                          | Censys API ID                          |
| `CENSYS_API_SECRET`   | *(empty)*                          | Censys API secret                      |
| `NVD_API_KEY`         | *(empty)*                          | NVD vulnerability DB key               |
| `OTX_API_KEY`         | *(empty)*                          | OTX threat intel key                   |
| `HUNTER_API_KEY`      | *(empty)*                          | Hunter.io email finder key             |
| `CORS_ORIGINS`        | `["http://localhost:3000","http://localhost:8000"]` | Allowed CORS origins |
| `ALLOWED_HOSTS`       | `["*"]`                            | Trusted host middleware                |

---

## Docker Alternative

```bash
docker-compose up -d
```

This starts: PostgreSQL, Redis, Qdrant, Backend, Worker, Frontend (nginx), Prometheus.

- Backend: http://localhost:8000
- Frontend: http://localhost:3000
- Prometheus: http://localhost:9090

---

## Stopping Services

### Windows
```batch
stop.bat
```

### Linux / macOS
```bash
bash stop.sh
```

---

## Troubleshooting

### 1. `ModuleNotFoundError: No module named 'bcrypt'`
```bash
pip install bcrypt>=4.2.0
```

### 2. `sqlite3.ProgrammingError: SQLite objects created in a thread can only be used in that same thread`
This is fixed in the latest code. If you see this error, ensure you're running the updated `scheduler.py`.

### 3. Port 8000 already in use
```bash
# Windows:
netstat -aon | findstr :8000
taskkill /F /PID <PID>

# Linux:
fuser -k 8000/tcp
```

### 4. `redis.exceptions.ConnectionError: Error connecting to localhost:6379`
Redis is optional. Without it, Taskiq uses InMemoryBroker. If you need Redis:
```bash
# Docker:
docker run -d --name redis -p 6379:6379 redis:7-alpine
```

### 5. `aiosmtplib.errors.SMTPConnectError`
Email alerts require valid SMTP settings in `.env`. Set `ALERT_EMAIL_ENABLED=false` to disable.
