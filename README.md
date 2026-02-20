# Manzen ISMS Backend

The REST API backend for the Manzen Information Security Management System (ISMS). Built with **Fastify**, **TypeScript**, **Prisma**, and **PostgreSQL**. Deployed on [Railway](https://railway.app).

**Live API:** `https://ismsbackend.bitcoingames1346.com`  
**Swagger docs:** `https://ismsbackend.bitcoingames1346.com/docs`  
**Frontend repo:** [Manzen](https://github.com/vinmnit159/Manzen)  
**MDM agent repo:** [manzen-mdm-agent](https://github.com/vinmnit159/manzen-mdm-agent)

---

## System overview

```
Manzen Web UI (React)
        │  JWT Bearer token
        ▼
isms-backend (this repo)
        │  Prisma ORM
        ▼
PostgreSQL (Railway)

Mac Device
        │  API key + HMAC-SHA256 signature
        ▼
/api/agent/checkin → auto-risk engine → Risk + Evidence records

GitHub OAuth
        │
        ▼
/integrations/github → repo scan → Evidence + Asset records
```

---

## Tech stack

| Layer | Technology |
|---|---|
| Runtime | Node.js 20 |
| Framework | Fastify 4 |
| Language | TypeScript 5 |
| ORM | Prisma 5 |
| Database | PostgreSQL 15 |
| Auth | JWT (HS256) + Google OAuth + bcrypt |
| Encryption | AES-256-GCM (for stored OAuth tokens) |
| File storage | Local disk via `@fastify/multipart` + `@fastify/static` |
| Logging | Pino |
| Deployment | Railway (Nixpacks build) |

---

## Requirements

- Node.js 18+
- PostgreSQL 12+
- npm

---

## Local setup

```bash
git clone git@github.com:vinmnit159/isms-backend.git
cd isms-backend
npm install
```

Copy and fill in the environment file:

```bash
cp .env.example .env
```

Minimum required variables:

```env
DATABASE_URL="postgresql://user:password@localhost:5432/isms_db"
JWT_SECRET="any-long-random-string"
ENCRYPTION_KEY="64-hex-chars-random"   # 32 bytes = openssl rand -hex 32
CORS_ORIGIN="http://localhost:5173"
```

Optional (needed only for OAuth integrations):

```env
GOOGLE_CLIENT_ID=""
GOOGLE_CLIENT_SECRET=""
GITHUB_CLIENT_ID=""
GITHUB_CLIENT_SECRET=""
```

Start a local PostgreSQL instance (or use Docker):

```bash
docker compose up -d db
```

Apply the schema and seed ISO 27001 controls:

```bash
npx prisma db push
npm run seed
```

Run in development mode (hot reload):

```bash
npm run dev
```

The API is now available at `http://localhost:3000`.

---

## Project structure

```
isms-backend/
├── prisma/
│   ├── schema.prisma          # Single source of truth for the database schema
│   ├── migrations/            # SQL migration history (committed, applied via db push on Railway)
│   └── seed.ts                # Populates ISO 27001 Annex A controls on first run
│
├── src/
│   ├── server.ts              # Process entry point — starts Fastify, handles signals
│   ├── app.ts                 # Registers all plugins, middleware, and route modules
│   │
│   ├── config/
│   │   └── env.ts             # Zod-validated environment variables (fails fast on startup)
│   │
│   ├── lib/
│   │   ├── prisma.ts          # Singleton PrismaClient instance
│   │   ├── rbac.ts            # Role enum, Permission enum, requirePermission() hook
│   │   ├── auth-middleware.ts # authenticate() hook — verifies JWT, attaches user to request
│   │   ├── crypto.ts          # AES-256-GCM encrypt/decrypt for OAuth token storage
│   │   ├── activity-logger.ts # logActivity() — fire-and-forget audit log writes
│   │   ├── file-storage.ts    # Helpers for saving/deleting uploaded files from disk
│   │   └── seed.ts            # ISO 27001 Annex A control seeder
│   │
│   ├── plugins/
│   │   ├── jwt.ts             # Registers @fastify/jwt with the secret from env
│   │   └── swagger.ts         # OpenAPI spec configuration
│   │
│   ├── jobs/
│   │   └── github-scan.ts     # node-cron job: scans GitHub repos daily at 02:00 UTC
│   │
│   └── modules/               # One directory per domain area
│       ├── auth/
│       │   ├── routes.ts      # POST /api/auth/register, /login, /me, /logout
│       │   ├── service.ts     # Password hashing, JWT signing
│       │   └── google.ts      # Google OAuth callback handler
│       │
│       ├── users/
│       │   └── routes.ts      # GET/PUT/DELETE /api/users — user management + git account mapping
│       │
│       ├── assets/
│       │   └── routes.ts      # CRUD /api/assets — asset inventory
│       │
│       ├── risks/
│       │   └── routes.ts      # CRUD /api/risks + /overview + /risk-score
│       │
│       ├── controls/
│       │   └── routes.ts      # CRUD /api/controls — ISO 27001 Annex A controls (SOA)
│       │
│       ├── evidence/
│       │   └── routes.ts      # CRUD /api/evidence — file uploads + automated evidence
│       │
│       ├── policies/
│       │   └── routes.ts      # CRUD /api/policies — policy document management
│       │
│       ├── audits/
│       │   └── routes.ts      # CRUD /api/audits + findings
│       │
│       ├── activity-logs/
│       │   └── routes.ts      # GET /api/activity-logs — recent audit trail
│       │
│       ├── setup/
│       │   └── routes.ts      # POST /api/setup — first-run org + admin user creation
│       │
│       ├── integrations/
│       │   ├── routes.ts          # GitHub OAuth connect/disconnect, scan trigger
│       │   ├── github-collector.ts # Calls GitHub API to inspect repos for compliance
│       │   └── github-asset-risk.ts # Creates Asset + Risk records from scan results
│       │
│       ├── mdm/
│       │   └── routes.ts      # Admin MDM routes: tokens, device list, overview
│       │
│       └── agent/
│           └── routes.ts      # Device-facing routes: enroll + checkin + auto-risk engine
│
├── Dockerfile                 # Multi-stage build (builder → production)
├── docker-compose.yml         # Local dev: PostgreSQL + Redis + API
├── railway.json               # Railway deploy config (start command, healthcheck)
└── tsconfig.json
```

---

## API reference

### Authentication

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/auth/register` | None | Create account (first user becomes org admin) |
| POST | `/api/auth/login` | None | Email + password login, returns JWT |
| GET | `/api/auth/me` | JWT | Current user profile |
| GET | `/integrations/github` | JWT | Start GitHub OAuth flow |
| GET | `/integrations/github/callback` | None | GitHub OAuth callback |

### Users & access

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/users` | JWT | List all org users with linked GitHub accounts |
| PUT | `/api/users/:id` | JWT (admin) | Update user role or name |
| DELETE | `/api/users/:id` | JWT (admin) | Remove user from org |
| GET | `/api/users/git-accounts/list` | JWT | All GitHub → ISMS user mappings |
| GET | `/api/users/git-accounts/github-members` | JWT | Live GitHub org members (needs integration) |
| POST | `/api/users/git-accounts/map` | JWT | Link a GitHub account to an ISMS user |
| DELETE | `/api/users/git-accounts/:id` | JWT | Unlink a GitHub account |

### Assets

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/assets` | JWT | All assets |
| POST | `/api/assets` | JWT | Create asset |
| PUT | `/api/assets/:id` | JWT | Update asset |
| DELETE | `/api/assets/:id` | JWT | Delete asset |
| GET | `/api/assets/distribution` | JWT | Count by asset type |

### Risks

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/risks` | JWT | All risks |
| GET | `/api/risks/overview` | JWT | Summary counts by status and level |
| POST | `/api/risks` | JWT | Create risk |
| PUT | `/api/risks/:id` | JWT | Update risk |
| DELETE | `/api/risks/:id` | JWT | Delete risk |

### Controls (ISO 27001 Annex A SOA)

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/controls` | JWT | All controls with implementation status |
| POST | `/api/controls` | JWT | Create control |
| PUT | `/api/controls/:id` | JWT | Update status / justification |

### Evidence

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/evidence` | JWT | All evidence records |
| POST | `/api/evidence` | JWT | Upload file evidence (multipart) |
| DELETE | `/api/evidence/:id` | JWT | Delete evidence |

### Policies

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/api/policies` | JWT | All policy documents |
| POST | `/api/policies` | JWT | Upload policy (multipart) |
| GET | `/files/:filename` | None | Serve uploaded file |

### MDM — admin

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/mdm/tokens` | JWT (admin) | Create enrollment token (24h TTL) |
| GET | `/api/mdm/tokens` | JWT (admin) | List tokens |
| DELETE | `/api/mdm/tokens/:id` | JWT (admin) | Revoke token |
| GET | `/api/mdm/devices` | JWT | List managed endpoints |
| GET | `/api/mdm/devices/:id/checkins` | JWT | Checkin history for a device |
| DELETE | `/api/mdm/devices/:id` | JWT (admin) | Revoke device |
| GET | `/api/mdm/overview` | JWT | Total / compliant / non-compliant counts |

### MDM — agent (device-facing, no user JWT)

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/api/agent/enroll` | None (token in body) | One-time device enrollment |
| POST | `/api/agent/checkin` | Bearer API key | Submit posture snapshot |

### Integrations

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/integrations/status` | JWT | GitHub integration status + repo list |
| GET | `/integrations/github` | JWT | Redirect to GitHub OAuth |
| GET | `/integrations/github/callback` | None | OAuth callback |
| POST | `/integrations/github/scan` | JWT | Trigger immediate repo scan |
| DELETE | `/integrations/github` | JWT | Disconnect GitHub |

---

## Database schema

```
Organization
  └── User (many)
        └── UserGitAccount (many)       ← GitHub username ↔ ISMS user mapping
  └── Asset (many)
        ├── DeviceCompliance (1:1)       ← latest posture snapshot
        ├── DeviceCheckin (many)         ← full audit log of every agent check-in
        └── DeviceEnrollment (1:1)       ← API key hash + revocation state
  └── Control (many)                    ← ISO 27001 Annex A controls
        └── Evidence (many)             ← files + automated scan results
  └── Risk (many)
        └── RiskTreatment (many)        ← links Risk to Control
  └── Policy (many)
  └── Audit (many)
        └── AuditFinding (many)
  └── Integration (many)                ← GitHub OAuth token (AES-256 encrypted)
        └── GitHubRepo (many)

EnrollmentToken                         ← standalone, org-scoped, one-time use
ActivityLog                             ← append-only audit trail
```

---

## Role-based access control

Roles in priority order: `SUPER_ADMIN` → `ORG_ADMIN` → `SECURITY_OWNER` → `AUDITOR` → `CONTRIBUTOR` → `VIEWER`

The `requirePermission(Permission.X)` hook in `src/lib/rbac.ts` is applied per route. Each role has a fixed set of permissions defined in the `rolePermissions` map — there is no runtime configuration.

---

## Auto-risk engine (MDM)

When a device checks in, `src/modules/agent/routes.ts` runs a rule table against the posture payload:

| Posture field | ISO control | Risk created if `false` |
|---|---|---|
| `diskEncryptionEnabled` | A.8.24 | Endpoint without disk encryption (HIGH) |
| `screenLockEnabled` | A.5.15 | Device without automatic screen lock (MEDIUM) |
| `firewallEnabled` | A.8.20 | Endpoint firewall disabled (MEDIUM) |
| `systemIntegrityEnabled` | A.8.7 | SIP disabled on endpoint (HIGH) |
| `autoUpdateEnabled` | A.8.8 | Automatic OS updates disabled (MEDIUM) |

- If a check fails and no open risk exists → creates `Risk` + `Evidence` + `RiskTreatment`
- If a check passes and an open risk exists → auto-mitigates it (status → `MITIGATED`)

---

## GitHub integration & evidence collection

`src/modules/integrations/github-collector.ts` inspects each repo for:

| Check | ISO control |
|---|---|
| Branch protection rules | A.8.32 |
| Commit signing | A.8.24 |
| CI/CD workflow present | A.8.25 |
| Collaborator access (public vs private) | A.5.15 |

Results are stored as `Evidence` records and linked to the matching `Control`. A `node-cron` job re-runs the scan daily at 02:00 UTC (`src/jobs/github-scan.ts`).

---

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `DATABASE_URL` | Yes | PostgreSQL connection string |
| `JWT_SECRET` | Yes | Secret for signing JWTs |
| `ENCRYPTION_KEY` | Yes | 64-char hex string for AES-256 (store OAuth tokens) |
| `CORS_ORIGIN` | Yes | Frontend URL allowed by CORS |
| `PORT` | No | Default `3000` |
| `LOG_LEVEL` | No | Default `info` |
| `GOOGLE_CLIENT_ID` | OAuth | Google SSO |
| `GOOGLE_CLIENT_SECRET` | OAuth | Google SSO |
| `GITHUB_CLIENT_ID` | OAuth | GitHub integration |
| `GITHUB_CLIENT_SECRET` | OAuth | GitHub integration |
| `UPLOAD_DIR` | No | Default `./uploads` |
| `MAX_FILE_SIZE` | No | Default `52428800` (50 MB) |

---

## Railway deployment

Railway runs the app using Nixpacks. The start command is:

```bash
npm run start:safe
# expands to: npx prisma db push --skip-generate && node dist/server.js
```

`prisma db push` syncs the schema to the Railway PostgreSQL database on every deploy without needing a migrations table. The build step runs `tsc` to compile TypeScript to `dist/`.

The `railway.json` at the repo root configures:
- Build: Nixpacks
- Start: `npm run start:safe`
- Healthcheck: `GET /health` (returns `{ status: "ok" }`)
- Restart policy: on failure

---

## Docker (local)

```bash
# Start database only
docker compose up -d db

# Start everything (db + api)
docker compose up

# Build production image
docker build -t isms-backend .
```

---

## Adding a new module

1. Create `src/modules/<name>/routes.ts` exporting an `async function <name>Routes(app: FastifyInstance)`
2. Add routes inside using `app.get/post/put/delete`
3. Protect routes with `{ onRequest: [authenticate] }` or `{ onRequest: [requirePermission(Permission.X)] }`
4. Import and register in `src/app.ts`: `app.register(<name>Routes, { prefix: '/api/<name>' })`
5. If new database tables are needed, add them to `prisma/schema.prisma` and run `npx prisma db push` locally

---

## Scripts

```bash
npm run dev          # Hot-reload development server (tsx watch)
npm run build        # Compile TypeScript → dist/
npm start            # Run compiled server
npm run start:safe   # db push + start (used by Railway)
npm run seed         # Seed ISO 27001 Annex A controls
npm test             # Jest test suite
npm run lint         # ESLint
npm run lint:fix     # ESLint with auto-fix
```
