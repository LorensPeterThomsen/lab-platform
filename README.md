# lab-platform

Samlet laboratorieplatform til:

- login / auth
- temperatur-overvågning
- livelink feed
- dashboard / websocket
- nginx reverse proxy
- PostgreSQL database

Systemet kører i Docker Compose på én server.

## Struktur

- `docker-compose.yml` – samlet stack
- `services/login_server/` – C++ login/auth service
- `services/dashboard_server/` – C++ dashboard/websocket service
- `services/livelinkd/` – C++ livelink feed service
- `nginx/` – nginx config og Dockerfile
- `frontend/public/` – statiske frontend-filer
- `config/` – lokal runtime-konfiguration (fx tokens-fil)
- `data/postgres/` – PostgreSQL data
- `data/backups/` – database-backups
- `scripts/` – hjælpe-scripts

## Services

### postgres
Intern PostgreSQL database i Docker.

### login_server
Auth/login backend i C++.
Kører bag nginx.

### livelinkd
Læser fra database og udstiller feed til dashboard_server.

### dashboard_server
WebSocket / dashboard backend i C++.

### nginx
Public entrypoint på 80/443.
Serverer frontend og proxyer til interne services.

## Krav

- Docker
- Docker Compose
- gyldig `.env`
- gyldige certifikater i `/etc/letsencrypt`
- `config/ds_tokens.json`

## Start

```bash
docker compose up -d --build


PGPASSWORD='...' pg_restore \
  -h 127.0.0.1 \
  -p 55432 \
  -U lptsql \
  -d lptdb \
  data/backups/filnavn.dump
