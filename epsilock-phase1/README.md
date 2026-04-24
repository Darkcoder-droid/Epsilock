# EPSILOCK Demo (Main Node + User Nodes + Attacker Node)

EPSILOCK runs as three demo apps:

- `main-node/`: admin panel + HTTPS/WSS server (`/ws`)
- `user-node/`: user chat node dashboards that connect to main node over WSS
- `attacker-node/`: separate educational dashboard that only receives intentionally mirrored encrypted packet copies

Important: this is an educational simulation for hackathon demos. It does not build real sniffing/MITM tooling and does not claim to be unhackable.

## Security baseline

- HTTPS/WSS transport (TLS cert paths from env)
- JWT auth with token version checks
- bcrypt password hashing
- AES-256-GCM demo packet encryption (`DEMO_SHARED_KEY`)
- No persistent chat plaintext storage
- No plaintext cover payload storage
- Only metadata (`PacketMeta`, `NodeSession`, `Incident`) is persisted

## How attacker demo works

- Main node can mirror encrypted packet metadata + crypto envelope to attacker-node.
- Attacker-node can optionally attempt demo decryption if `DEMO_SHARED_KEY` is configured ("Demo leaked key mode").
- Decrypted previews are in-memory UI only on attacker-node and are never persisted.

Cover traffic wording used in UI:

- "Cover traffic reduces metadata leakage and timing-analysis confidence."
- It does **not** make the system unhackable.

## TLS certificates

Generate local dev certs:

```bash
npm run certs
```

## Setup

1. Copy env:

```bash
cp .env.example .env
```

2. Install dependencies:

```bash
npm install
```

3. Generate certs:

```bash
npm run certs
```

4. Seed admin account:

```bash
npm run seed:admin
```

Default admin:

- username: `admin`
- password: `admin123`

## Run apps

Terminal 1:

```bash
npm run dev:main
```

Terminal 2:

```bash
npm run dev:node1
```

Terminal 3:

```bash
npm run dev:node2
```

Terminal 4:

```bash
npm run dev:attacker
```

Default URLs:

- Main admin: `https://localhost:8443`
- User node 1: `https://localhost:3001`
- User node 2: `https://localhost:3002`
- Attacker node: `https://localhost:4001/attacker`

## Admin navigation

- `/admin`
- `/admin/users`
- `/admin/rooms`
- `/admin/nodes`
- `/admin/incidents`
- `/admin/attacker-demo`
- `/admin/security-settings`

## Security settings (live, no restart)

Open `/admin/security-settings`.

You can configure:

- `ATTACKER_DEMO_ENABLED`
- `COVER_TRAFFIC_ENABLED`
- `COVER_TRAFFIC_INTERVAL_MS`
- `COVER_TRAFFIC_JITTER_MS`
- `COVER_TRAFFIC_RATIO`

When saved:

- Main node broadcasts `SECURITY_SETTINGS_UPDATED` to admin sockets
- Main node broadcasts `COVER_TRAFFIC_CONFIG_UPDATED` to connected user nodes
- Main node broadcasts `ATTACKER_DEMO_SETTINGS_UPDATED` to attacker-node
- User nodes start/stop/reconfigure cover packets immediately
- Attacker dashboard updates instantly

## WSS role handling

Main `/ws` supports:

- admin socket (`client=admin`, JWT)
- user node sockets (JWT + `nodeId` + `userId`)
- attacker demo socket (`client=attacker`, `ATTACKER_DEMO_TOKEN`)

Attacker socket is accepted only when:

- `NODE_ENV !== production` OR attacker demo is enabled
- token matches `ATTACKER_DEMO_TOKEN`
- origin passes allowed origin rules

## Hackathon demo flow

1. Start all 4 processes (main, node1, node2, attacker).
2. In admin, create users and a room; add both users to room.
3. Log in from both user nodes, select room, join room, send message.
4. Open attacker dashboard and observe packets with cover traffic OFF.
5. In `/admin/security-settings`, turn cover traffic ON.
6. Send similar messages again.
7. Observe attacker dashboard now receives mixed real + cover packets and confidence drops to LOW/MEDIUM.
8. Explain: encryption protects content; cover traffic adds noise to reduce metadata/timing-analysis confidence.

## User-node chat gating checks

Chat controls are enabled only when all are true:

1. WSS connected
2. Node authenticated (`NODE_AUTH_OK`)
3. Room joined (`ROOM_JOIN_OK`)

Manual checks:

1. Open user chat page: message/file controls stay disabled.
2. Before WSS is connected: controls disabled.
3. After WSS open but before node auth: controls disabled.
4. After `NODE_AUTH_OK` but before join: controls disabled, room join available.
5. Select room but do not join: controls disabled.
6. Click join room: controls remain disabled while waiting.
7. After `ROOM_JOIN_OK`: controls enabled.
8. Try invalid/fake room send: server returns `SEND_DENIED`, no broadcast.
9. Disconnect WSS: controls disable immediately.
10. Freeze room in admin: sends are denied and user sees denied reason.

## Received message rendering test

1. Start main node.
2. Start user node 1 and user node 2.
3. Login as two different users.
4. Join the same room from both dashboards.
5. Send a message from user 1.
6. Expected: user 2 sees the message bubble in chat log.
7. Expected: user 1 sees own message exactly once (server echo).
8. Turn cover traffic ON from admin settings.
9. Expected: cover packets appear in attacker demo, not in user chat UI.
10. Join different rooms.
11. Expected: messages do not cross rooms.
12. Freeze room in admin.
13. Expected: send denied (or input disabled) and no new messages rendered.

## Environment variables (highlights)

- `MAIN_NODE_PORT=8443`
- `USER_NODE_1_PORT=3001`
- `USER_NODE_2_PORT=3002`
- `ATTACKER_NODE_PORT=4001`
- `MAIN_NODE_WSS_URL=wss://localhost:8443/ws`
- `ATTACKER_NODE_URL=https://localhost:4001/attacker`
- `ATTACKER_DEMO_ENABLED=true`
- `ATTACKER_DEMO_TOKEN=change-this-demo-token`
- `DEMO_SHARED_KEY=<hex-64 or passphrase>`

## NPM scripts

- `npm run dev:main`
- `npm run dev:node1`
- `npm run dev:node2`
- `npm run dev:attacker`
- `npm run certs`
- `npm run seed:admin`
