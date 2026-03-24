# TwoSub2API

<div align="center">

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](https://golang.org/)
[![Vue](https://img.shields.io/badge/Vue-3.4+-4FC08D.svg)](https://vuejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D.svg)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

**AI API Gateway Platform — Subscription Quota Distribution & Management**

English | [中文](README_CN.md)

</div>

---

## Overview

TwoSub2API is an AI API gateway platform designed to distribute and manage API quotas from AI product subscriptions (like Claude Code $200/month). Users access upstream AI services through platform-generated API Keys, while the platform handles authentication, billing, load balancing, and request forwarding.

## Features

- **Multi-Account Management** - Support multiple upstream account types (OAuth, API Key)
- **API Key Distribution** - Generate and manage API Keys for users
- **Precise Billing** - Token-level usage tracking and cost calculation
- **Smart Scheduling** - Intelligent account selection with sticky sessions
- **Concurrency Control** - Per-user and per-account concurrency limits
- **Rate Limiting** - Configurable request and token rate limits
- **Admin Dashboard** - Web interface for monitoring and management

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Go 1.26+, Gin, Ent |
| Frontend | Vue 3.4+, Vite 5+, TailwindCSS |
| Database | PostgreSQL 15+ |
| Cache/Queue | Redis 7+ |

---

## Deployment

### Docker Image (Alibaba Cloud Registry)

Pull the latest image directly from Alibaba Cloud Container Registry:

```bash
# Pull latest
docker pull crpi-pxlqri5n5thqtf6f.cn-guangzhou.personal.cr.aliyuncs.com/miaocg/twosub2api:latest

# Or pull a specific version
docker pull crpi-pxlqri5n5thqtf6f.cn-guangzhou.personal.cr.aliyuncs.com/miaocg/twosub2api:v0.2.65
```

### Docker Compose (Recommended)

Deploy with Docker Compose, including PostgreSQL and Redis containers.

#### Prerequisites

- Docker 20.10+
- Docker Compose v2+

#### Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/miaocg1789/twosub2api.git
cd twosub2api/deploy

# 2. Copy environment configuration
cp .env.example .env

# 3. Edit configuration (generate secure passwords)
nano .env
```

**Required configuration in `.env`:**

```bash
# PostgreSQL password (REQUIRED)
POSTGRES_PASSWORD=your_secure_password_here

# JWT Secret (RECOMMENDED - keeps users logged in after restart)
JWT_SECRET=your_jwt_secret_here

# TOTP Encryption Key (RECOMMENDED - preserves 2FA after restart)
TOTP_ENCRYPTION_KEY=your_totp_key_here

# Optional: Admin account
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=your_admin_password

# Optional: Custom port
SERVER_PORT=8080
```

**Generate secure secrets:**
```bash
openssl rand -hex 32   # Use for JWT_SECRET, TOTP_ENCRYPTION_KEY, POSTGRES_PASSWORD
```

```bash
# 4. Create data directories
mkdir -p data postgres_data redis_data

# 5. Start all services
docker-compose -f docker-compose.local.yml up -d

# 6. View logs
docker-compose -f docker-compose.local.yml logs -f sub2api
```

#### Access

Open `http://YOUR_SERVER_IP:8080` in your browser.

#### Upgrade

```bash
# Pull latest image and recreate container
docker-compose -f docker-compose.local.yml pull
docker-compose -f docker-compose.local.yml up -d
```

#### Easy Migration

```bash
# On source server
docker-compose -f docker-compose.local.yml down
cd .. && tar czf twosub2api-backup.tar.gz twosub2api-deploy/

# On new server
tar xzf twosub2api-backup.tar.gz && cd twosub2api-deploy/
docker-compose -f docker-compose.local.yml up -d
```

---

### Build from Source

Build and run from source code for development or customization.

#### Prerequisites

- Go 1.26+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+

#### Build Steps

```bash
# 1. Clone the repository
git clone https://github.com/miaocg1789/twosub2api.git
cd twosub2api

# 2. Install pnpm (if not already installed)
npm install -g pnpm

# 3. Build frontend
cd frontend
pnpm install
pnpm run build
# Output will be in ../backend/internal/web/dist/

# 4. Build backend with embedded frontend
cd ../backend
go build -tags embed -o sub2api ./cmd/server

# 5. Create configuration file
cp ../deploy/config.example.yaml ./config.yaml

# 6. Edit configuration
nano config.yaml
```

> **Note:** The `-tags embed` flag embeds the frontend into the binary. Without this flag, the binary will not serve the frontend UI.

**Key configuration in `config.yaml`:**

```yaml
server:
  host: "0.0.0.0"
  port: 8080
  mode: "release"

database:
  host: "localhost"
  port: 5432
  user: "postgres"
  password: "your_password"
  dbname: "sub2api"

redis:
  host: "localhost"
  port: 6379
  password: ""

jwt:
  secret: "change-this-to-a-secure-random-string"
  expire_hour: 24

default:
  user_concurrency: 5
  user_balance: 0
  api_key_prefix: "sk-"
  rate_multiplier: 1.0
```

```bash
# 6. Run the application
./sub2api
```

#### Development Mode

```bash
# Backend (with hot reload)
cd backend
go run ./cmd/server

# Frontend (with hot reload)
cd frontend
pnpm run dev
```

---

## Simple Mode

Simple Mode is designed for individual developers or internal teams who want quick access without full SaaS features.

- Enable: Set environment variable `RUN_MODE=simple`
- Hides SaaS-related features and skips billing process

---

## Project Structure

```
twosub2api/
├── backend/                  # Go backend service
│   ├── cmd/server/           # Application entry
│   ├── internal/             # Internal modules
│   │   ├── config/           # Configuration
│   │   ├── service/          # Business logic
│   │   ├── handler/          # HTTP handlers
│   │   └── gateway/          # API gateway core
│   └── ent/                  # Database schema (Ent ORM)
│
├── frontend/                 # Vue 3 frontend
│   └── src/
│       ├── api/              # API calls
│       ├── stores/           # State management
│       ├── views/            # Page components
│       └── components/       # Reusable components
│
└── deploy/                   # Deployment files
    ├── docker-compose.yml    # Docker Compose configuration
    └── .env.example          # Environment variables template
```

## Disclaimer

> **Please read carefully before using this project:**
>
> This project is for technical learning and research purposes only. The author assumes no responsibility for account suspension, service interruption, or any other losses caused by the use of this project.

---

## License

MIT License

---

<div align="center">

**If you find this project useful, please give it a star!**

</div>
