# TwoSub2API

<div align="center">

[![Go](https://img.shields.io/badge/Go-1.26+-00ADD8.svg)](https://golang.org/)
[![Vue](https://img.shields.io/badge/Vue-3.4+-4FC08D.svg)](https://vuejs.org/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15+-336791.svg)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7+-DC382D.svg)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg)](https://www.docker.com/)

**AI API 网关平台 — 订阅配额分发管理**

[English](README.md) | 中文

</div>

---

## 项目概述

TwoSub2API 是一个 AI API 网关平台，用于分发和管理 AI 产品订阅（如 Claude Code $200/月）的 API 配额。用户通过平台生成的 API Key 调用上游 AI 服务，平台负责鉴权、计费、负载均衡和请求转发。

## 核心功能

- **多账号管理** — 支持多种上游账号类型（OAuth、API Key）
- **API Key 分发** — 为用户生成和管理 API Key
- **精确计费** — Token 级别的用量追踪和成本计算，支持按次计费
- **智能调度** — 智能账号选择，支持粘性会话
- **并发控制** — 用户级和账号级并发限制
- **速率限制** — 可配置的请求和 Token 速率限制
- **管理后台** — Web 界面进行监控和管理

## 技术栈

| 组件 | 技术 |
|------|------|
| 后端 | Go 1.26+, Gin, Ent |
| 前端 | Vue 3.4+, Vite 5+, TailwindCSS |
| 数据库 | PostgreSQL 15+ |
| 缓存/队列 | Redis 7+ |

---

## 部署方式

### Docker 镜像（阿里云容器镜像服务）

直接从阿里云容器镜像仓库拉取：

```bash
# 拉取最新版
docker pull crpi-pxlqri5n5thqtf6f.cn-guangzhou.personal.cr.aliyuncs.com/miaocg/twosub2api:latest

# 拉取指定版本
docker pull crpi-pxlqri5n5thqtf6f.cn-guangzhou.personal.cr.aliyuncs.com/miaocg/twosub2api:v0.2.65
```

### Docker Compose 部署（推荐）

使用 Docker Compose 部署，包含 PostgreSQL 和 Redis 容器。

#### 前置条件

- Docker 20.10+
- Docker Compose v2+

#### 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/miaocg1789/twosub2api.git
cd twosub2api/deploy

# 2. 复制环境配置文件
cp .env.example .env

# 3. 编辑配置
nano .env
```

**`.env` 必须配置项：**

```bash
# PostgreSQL 密码（必需）
POSTGRES_PASSWORD=your_secure_password_here

# JWT 密钥（推荐 - 重启后保持用户登录状态）
JWT_SECRET=your_jwt_secret_here

# TOTP 加密密钥（推荐 - 重启后保留双因素认证）
TOTP_ENCRYPTION_KEY=your_totp_key_here

# 可选：管理员账号
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=your_admin_password

# 可选：自定义端口
SERVER_PORT=8080
```

**生成安全密钥：**
```bash
openssl rand -hex 32   # 分别用于 JWT_SECRET、TOTP_ENCRYPTION_KEY、POSTGRES_PASSWORD
```

```bash
# 4. 创建数据目录
mkdir -p data postgres_data redis_data

# 5. 启动所有服务
docker-compose -f docker-compose.local.yml up -d

# 6. 查看日志
docker-compose -f docker-compose.local.yml logs -f sub2api
```

#### 访问

在浏览器中打开 `http://你的服务器IP:8080`

#### 升级

```bash
# 拉取最新镜像并重建容器
docker-compose -f docker-compose.local.yml pull
docker-compose -f docker-compose.local.yml up -d
```

#### 轻松迁移

```bash
# 源服务器
docker-compose -f docker-compose.local.yml down
cd .. && tar czf twosub2api-backup.tar.gz twosub2api-deploy/

# 新服务器
tar xzf twosub2api-backup.tar.gz && cd twosub2api-deploy/
docker-compose -f docker-compose.local.yml up -d
```

---

### 源码编译

从源码编译安装，适合开发或定制需求。

#### 前置条件

- Go 1.26+
- Node.js 18+
- PostgreSQL 15+
- Redis 7+

#### 编译步骤

```bash
# 1. 克隆仓库
git clone https://github.com/miaocg1789/twosub2api.git
cd twosub2api

# 2. 安装 pnpm
npm install -g pnpm

# 3. 编译前端
cd frontend
pnpm install
pnpm run build

# 4. 编译后端（嵌入前端）
cd ../backend
go build -tags embed -o sub2api ./cmd/server

# 5. 创建配置文件
cp ../deploy/config.example.yaml ./config.yaml

# 6. 编辑配置
nano config.yaml

# 7. 运行
./sub2api
```

#### 开发模式

```bash
# 后端（支持热重载）
cd backend
go run ./cmd/server

# 前端（支持热重载）
cd frontend
pnpm run dev
```

---

## 简易模式

适合个人开发者或内部团队快速使用，不依赖完整 SaaS 功能。

- 启用方式：设置环境变量 `RUN_MODE=simple`
- 功能差异：隐藏 SaaS 相关功能，跳过计费流程

---

## 项目结构

```
twosub2api/
├── backend/                  # Go 后端服务
│   ├── cmd/server/           # 应用入口
│   ├── internal/             # 内部模块
│   │   ├── config/           # 配置管理
│   │   ├── service/          # 业务逻辑
│   │   ├── handler/          # HTTP 处理器
│   │   └── gateway/          # API 网关核心
│   └── ent/                  # 数据库模型 (Ent ORM)
│
├── frontend/                 # Vue 3 前端
│   └── src/
│       ├── api/              # API 调用
│       ├── stores/           # 状态管理
│       ├── views/            # 页面组件
│       └── components/       # 通用组件
│
└── deploy/                   # 部署文件
    ├── docker-compose.yml    # Docker Compose 配置
    └── .env.example          # 环境变量模板
```

## 免责声明

> **使用本项目前请仔细阅读：**
>
> 本项目仅供技术学习和研究使用，作者不对因使用本项目导致的账户封禁、服务中断或其他损失承担任何责任。

---

## 许可证

MIT License

---

<div align="center">

**如果觉得有用，请给个 Star 支持一下！**

</div>
