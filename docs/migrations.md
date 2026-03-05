# Database Migrations

OfSec V3 uses [Alembic](https://alembic.sqlalchemy.org/) for database schema management.
All commands should be run from the `backend/` directory.

## After changing any model in `backend/app/models/__init__.py`:

```bash
cd backend
alembic revision --autogenerate -m "describe_your_change"
# Review the generated file in alembic/versions/
alembic upgrade head
```

## Roll back one migration:

```bash
alembic downgrade -1
```

## Check current schema version:

```bash
alembic current
```

## View migration history:

```bash
alembic history --verbose
```

## First-time setup (existing database with tables):

If tables already exist from `create_all`, stamp the DB as current without re-running:

```bash
alembic stamp head
```

## First-time setup (empty database):

```bash
alembic upgrade head
```
