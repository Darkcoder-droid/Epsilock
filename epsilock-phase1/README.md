# EPSILOCK Phase 1

Phase 1 implementation: secure connection with multi-node chat setup.

Scope included:
- Main admin node server (`main-node`)
- Sender and receiver user node servers from the same codebase (`user-node`)
- JWT + secure cookies auth
- Role-based access (`admin`, `user`)
- WebSocket broker + real-time chat/file relay
- Session metadata tracking only (no message persistence)
- Temporary in-memory file transfer with expiry and one-time delivery

Out of scope for this phase:
- Threat detection engine
- Anomaly scoring enforcement
- Backup/recovery orchestration
- Hacker simulation

Future hooks are added in code as TODO comments.

## Architecture Summary

1. Main Node (`:4000` by default)
- Admin login/dashboard
- User creation and node assignment (sender/receiver)
- Node metadata + session metadata storage in MongoDB
- Tracks active socket sessions via WS broker
- Does not store chat message content

2. Sender Node (`:4001` by default)
- Same user dashboard template as receiver node
- `NODE_TYPE=sender`
- Bridges chat events to main node broker

3. Receiver Node (`:4002` by default)
- Same user dashboard template as sender node
- `NODE_TYPE=receiver`
- Receives relayed events from main node broker

## Data Models

- `User`: auth and node assignment
- `NodeRecord`: node identity/status/ws endpoint metadata
- `SessionLog`: room metadata only (`roomId`, participants, timestamps, status)

Message bodies and files are never persisted in MongoDB.

## Security Notes

- Passwords are hashed with bcrypt.
- JWT access tokens are short-lived (`ACCESS_TOKEN_TTL`, default `10m`).
- Cookies are `HttpOnly`, `SameSite=Strict`, `Secure`.
- WS connections validate JWT before socket access.
- TLS certs are configurable by env path.
- TLS 1.3 + ECC usage is documented in `scripts/generateCerts.md`.

## Setup

1. Install dependencies
```bash
cd epsilock-phase1
npm install
```

2. Create env file
```bash
cp .env.example .env
```

3. Start MongoDB locally (or update `MONGO_URI`).

4. Generate local certs (recommended)
```bash
# See full details:
cat scripts/generateCerts.md
```

5. Seed admin
```bash
npm run seed:admin
```
Seeded admin credentials:
- username: `admin`
- password: `admin123`

6. Start servers in three terminals
```bash
# Terminal 1
npm run start:main

# Terminal 2
npm run start:sender

# Terminal 3
npm run start:receiver
```

## Usage Flow

1. Open main node: `https://localhost:4000/auth/login`
2. Login as admin.
3. Create one sender user and one receiver user.
4. Pair users into a room on admin dashboard.
5. Open sender node login and receiver node login:
- `https://localhost:4001/auth/login`
- `https://localhost:4002/auth/login`
6. Login with assigned users, enter room, chat in real time, and share temporary files.

After refresh/logout, old messages disappear from UI.

## Env Variables

Required/used:
- `MONGO_URI`
- `JWT_SECRET`
- `MAIN_NODE_PORT`
- `SENDER_NODE_PORT`
- `RECEIVER_NODE_PORT`
- `TLS_KEY_PATH`
- `TLS_CERT_PATH`
- `NODE_TYPE`
- `NODE_ID`
- `MAIN_NODE_URL`

Optional:
- `ACCESS_TOKEN_TTL`
- `FILE_TTL_MS`
- `MAX_FILE_BYTES`

## Explicit Future Hooks in Code

- `TODO: Phase 2 threat detection hook on abnormal socket disconnects`
- `TODO: Phase 2 anomaly scoring middleware`
- `TODO: Phase 3 backup node recovery server`
- `TODO: token revocation and secure reconnection`
